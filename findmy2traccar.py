#!/usr/bin/env python3
import os,glob,datetime,argparse
import base64,json
import hashlib,codecs,struct
import requests
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from pypush_gsa_icloud import icloud_login_mobileme, generate_anisette_headers

previous_timestamps = {}

purge_loop_counter = 0
purge_loops = 120
sleep_time = 30
key_subfolder = '/keys'
traccar_url = 'localhost:5055'

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
    if id in previous_timestamps and timestamp in previous_timestamps[id]:
        return True
    else:
        return False

def purge_timestamps():
    now = int(time.time())
    three_days = 3 * 24 * 60 * 60

    for id in list(previous_timestamps.keys()):
        previous_timestamps[id] = [timestamp for timestamp in previous_timestamps[id] if now - timestamp < three_days]

        if not previous_timestamps[id]:
            del previous_timestamps[id]

def decode_tag(data):
    latitude = struct.unpack(">i", data[0:4])[0] / 10000000.0
    longitude = struct.unpack(">i", data[4:8])[0] / 10000000.0
    confidence = int.from_bytes(data[8:9], 'big')
    status = int.from_bytes(data[9:10], 'big')
    return {'lat': latitude, 'lon': longitude, 'conf': confidence, 'status':status}

def getAuth(regenerate=False, second_factor='sms'):
    CONFIG_PATH = os.path.dirname(os.path.realpath(__file__)) + "/auth.json"
    if os.path.exists(CONFIG_PATH) and not regenerate:
        with open(CONFIG_PATH, "r") as f: j = json.load(f)
    else:
        mobileme = icloud_login_mobileme(second_factor=second_factor)
        j = {'dsid': mobileme['dsid'], 'searchPartyToken': mobileme['delegates']['com.apple.mobileme']['service-data']['tokens']['searchPartyToken']}
        with open(CONFIG_PATH, "w") as f: json.dump(j, f)
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

def request_reports(names):
    unixEpoch = int(datetime.datetime.now().strftime('%s'))
    startdate = unixEpoch - 180
    data = { "search": [{"startDate": startdate *1000, "endDate": unixEpoch *1000, "ids": list(names.keys())}] }
    r = requests.post("https://gateway.icloud.com/acsnservice/fetch",
            auth=getAuth(),
            headers=generate_anisette_headers(),
            json=data)
    res = json.loads(r.content.decode())['results']
    return res

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
    tag = decode_tag(decrypted)
    return tag

def to_traccar(res, names, privkeys):
    i = 0
    unixEpoch = int(datetime.datetime.now().strftime('%s'))
    oldest_age = unixEpoch - 3600
    for report in res:
        s = requests.Session()
        priv = int.from_bytes(base64.b64decode(privkeys[report['id']]), 'big')
        data = base64.b64decode(report['payload'])
        timestamp = int.from_bytes(data[0:4], 'big') +978307200
        if not check_timestamp(names[report['id']], timestamp) and not timestamp <= oldest_age:
          tag = decrypt_tag(priv, data)
          url = 'http://'+ traccar_url + '/?id=' + names[report['id']] + '&lat=' + str(tag['lat']) + '&lon=' + str(tag['lon']) + '&altitude=0&timestamp=' + str(timestamp) + "&accuracy=" + str(conftoAcc(tag['conf'])) 
          add_timestamp(names[report['id']], timestamp)
          try:
            response = s.get(url, timeout=0.5)
            s.close
          except:
            pass
        i +=1

while True:
    privkeys, names = readkeyfiles()
    res = request_reports(names)
    to_traccar(res, names, privkeys)
    purge_loop_counter +=1
    if purge_loop_counter == purge_loops:
       purge_timestamps()
       purge_loop_counter = 0
    time.sleep(sleep_time)
