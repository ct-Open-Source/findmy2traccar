#!/usr/bin/env python3
import os, glob, datetime, argparse
import base64, json
import hashlib, codecs, struct
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from pypush_gsa_icloud import icloud_login_mobileme, generate_anisette_headers

previous_timestamps = {}
purge_loop_counter = 0
purge_loops = 120

key_subfolder = '/keys'
traccar_url = '192.168.7.170:5055'

def sha256(data):
    digest = hashlib.new("sha256")
    digest.update(data)
    return digest.digest()

def decrypt(enc_data, algorithm_dkey, mode):
    decryptor = Cipher(algorithm_dkey, mode, default_backend()).decryptor()
    return decryptor.update(enc_data) + decryptor.finalize()

def conftoAcc(conf):
    minConf = 50
    maxConf = 215
    minAcc = 0
    maxAcc = 80
    accuracy = maxAcc - ((conf - minConf) / (maxConf - minConf) * (maxAcc - minAcc))
    return int(accuracy)

def add_timestamp(id, timestamp):
    if id in previous_timestamps:
        previous_timestamps[id].append(timestamp)
    else:
        previous_timestamps[id] = [timestamp]

def check_timestamp(id, timestamp):
    return id in previous_timestamps and timestamp in previous_timestamps[id]

def purge_timestamps():
    now = int(time.time())
    three_days = 3 * 24 * 60 * 60
    for id in list(previous_timestamps.keys()):
        previous_timestamps[id] = [ts for ts in previous_timestamps[id] if now - ts < three_days]
        if not previous_timestamps[id]:
            del previous_timestamps[id]

def decode_tag(data):
    latitude = struct.unpack(">i", data[0:4])[0] / 10000000.0
    longitude = struct.unpack(">i", data[4:8])[0] / 10000000.0
    confidence = int.from_bytes(data[8:9], 'big')
    status = int.from_bytes(data[9:10], 'big')
    return {'lat': latitude, 'lon': longitude, 'conf': confidence, 'status': status}

def getAuth(regenerate=False, second_factor='sms'):
    CONFIG_PATH = os.path.dirname(os.path.realpath(__file__)) + "/auth.json"
    if os.path.exists(CONFIG_PATH) and not regenerate:
        with open(CONFIG_PATH, "r") as f:
            j = json.load(f)
    else:
        mobileme = icloud_login_mobileme(second_factor=second_factor)
        j = {'dsid': mobileme['dsid'], 'searchPartyToken': mobileme['delegates']['com.apple.mobileme']['service-data']['tokens']['searchPartyToken']}
        with open(CONFIG_PATH, "w") as f:
            json.dump(j, f)
    return (j['dsid'], j['searchPartyToken'])

def readkeyfiles():
    privkeys = {}
    names = {}
    for keyfile in glob.glob(os.path.dirname(os.path.realpath(__file__)) + key_subfolder + '/*.keys'):
        with open(keyfile) as f:
            hashed_adv = priv = None
            name = os.path.basename(keyfile)[:-5]
            for line in f:
                key = line.rstrip('\n').split(': ')
                if key[0] == 'Private key':
                    if hashed_adv and priv:
                        privkeys[hashed_adv] = priv
                        names[hashed_adv] = name
                        hashed_adv = None
                    priv = key[1]
                elif key[0] == 'Hashed adv key':
                    hashed_adv = key[1]
                if priv and hashed_adv:
                    privkeys[hashed_adv] = priv
                    names[hashed_adv] = name
    return privkeys, names

def chunk_keys(privkeys, names, chunk_size):
    keys = list(privkeys.keys())
    for i in range(0, len(keys), chunk_size):
        sub_keys = keys[i:i+chunk_size]
        yield ({k: privkeys[k] for k in sub_keys}, {k: names[k] for k in sub_keys})

def request_reports(privkeys, names, chunk_size=2, max_workers=6):
    unixEpoch = int(datetime.datetime.now().strftime('%s'))
    startdate = unixEpoch - 1800
    chunks = list(chunk_keys(privkeys, names, chunk_size))
    all_results = []

    def fetch_chunk(priv_chunk, name_chunk):
        #print(list(name_chunk.keys()))
        data = {
            "search": [{
                "startDate": startdate * 1000,
                "endDate": unixEpoch * 1000,
                "ids": list(name_chunk.keys())
            }]
        }
        try:
            r = requests.post("https://gateway.icloud.com/acsnservice/fetch",
                              auth=getAuth(),
                              headers=generate_anisette_headers(),
                              json=data)
            return json.loads(r.content.decode()).get('results', [])
        except Exception as e:
            print(f"Fehler bei Anfrage: {e}")
            return []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(fetch_chunk, p, n) for p, n in chunks]
        for future in as_completed(futures):
            all_results.extend(future.result())

    return all_results

def decrypt_tag(priv, data):
    adj = len(data) - 88
    eph_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), data[5+adj:62+adj])
    shared_key = ec.derive_private_key(priv, ec.SECP224R1(), default_backend()).exchange(ec.ECDH(), eph_key)
    symmetric_key = sha256(shared_key + b'\x00\x00\x00\x01' + data[5+adj:62+adj])
    decryption_key = symmetric_key[:16]
    iv = symmetric_key[16:]
    enc_data = data[62+adj:72+adj]
    tag = data[72+adj:]
    decrypted = decrypt(enc_data, algorithms.AES(decryption_key), modes.GCM(iv, tag))
    return decode_tag(decrypted)

def to_traccar(res, names, privkeys):
    unixEpoch = int(datetime.datetime.now().strftime('%s'))
    oldest_age = unixEpoch - 1800
    for report in res:
        s = requests.Session()
        priv = int.from_bytes(base64.b64decode(privkeys[report['id']]), 'big')
        data = base64.b64decode(report['payload'])
        timestamp = int.from_bytes(data[0:4], 'big') + 978307200
        if not check_timestamp(names[report['id']], timestamp) and not timestamp <= oldest_age:
            tag = decrypt_tag(priv, data)
            url = f"http://{traccar_url}/?id={names[report['id']]}&lat={tag['lat']}&lon={tag['lon']}&altitude=0&timestamp={timestamp}&accuracy={conftoAcc(tag['conf'])}"
            add_timestamp(names[report['id']], timestamp)
            #print(url)
            try:
                response = s.get(url, timeout=0.5)
                s.close()
            except:
                pass

while True:
    print("Starting new FindMy request round")
    privkeys, names = readkeyfiles()
    res = request_reports(privkeys, names, chunk_size=2, max_workers=20)
    to_traccar(res, names, privkeys)
    purge_loop_counter += 1
    if purge_loop_counter == purge_loops:
        purge_timestamps()
        print("Purged Timestamps")
        purge_loop_counter = 0
    print("FindMy round completed, sleeping 60 seconds")
    time.sleep(60)
