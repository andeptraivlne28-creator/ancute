import json, requests, threading, time
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request
import asyncio, aiohttp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser

key = b"Yg&tc%DEuh6%Zc^8"
iv = b"6oyZDr22E3ychjM%"

app = Flask(__name__)

account_index = 0
accounts_data = []
tokens = {}
used_uids = {}
gringay = None

tokens_lock = threading.Lock()
uids_ = threading.Lock()
accounts_lock = threading.Lock()

def load_accounts():
 global accounts_data
 try:
  with open('account.json', 'r') as f:
   accounts_data = json.load(f)
  print("{} ACC".format(len(accounts_data)))
 except (FileNotFoundError, json.JSONDecodeError):
  accounts_data = []

def get_next_accounts(num=250):
 global account_index, accounts_data
 with accounts_lock:
  if not accounts_data:
   load_accounts()
  if not accounts_data: return []
  selected_accounts = []
  for i in range(min(num, len(accounts_data))):
   if account_index >= len(accounts_data):
    account_index = 0
   uid, password = accounts_data[account_index]['data'].split(":", 1)
   selected_accounts.append((uid, password))
   account_index += 1
  return selected_accounts

def Encrypt(number):
 number = int(number)
 if number < 0: return False
 encoded_bytes = []
 while True:
  byte = number & 0x7F
  number >>= 7
  if number:
   byte |= 0x80
  encoded_bytes.append(byte)
  if not number: break
 return bytes(encoded_bytes)

def create_varint_field(field_number, value):
 field_header = (field_number << 3) | 0
 return Encrypt(field_header) + Encrypt(value)

def create_length_delimited_field(field_number, value):
 field_header = (field_number << 3) | 2
 encoded_value = value.encode() if isinstance(value, str) else value
 return Encrypt(field_header) + Encrypt(len(encoded_value)) + encoded_value

def create_protobuf_packet(fields):
 packet = bytearray()
 for field, value in fields.items():
  if isinstance(value, dict):
   nested_packet = create_protobuf_packet(value)
   packet.extend(create_length_delimited_field(field, nested_packet))
  elif isinstance(value, int):
   packet.extend(create_varint_field(field, value))
  elif isinstance(value, str) or isinstance(value, bytes):
   packet.extend(create_length_delimited_field(field, value))
 return packet

def parse_results(parsed_results):
 result_dict = {}
 for result in parsed_results:
  if result.field not in result_dict:
   result_dict[result.field] = []
  field_data = {}
  if result.wire_type in ["varint", "string", "bytes"]:
   field_data = result.data
  elif result.wire_type == "length_delimited":
   field_data = parse_results(result.data.results)
  result_dict[result.field].append(field_data)
 return {key: value[0] if len(value) == 1 else value for key, value in result_dict.items()}

def protobuf_dec(hex):
 try: return json.dumps(parse_results(Parser().parse(hex)), ensure_ascii=False)
 except: return "{}"

def encrypt_api(hex):
 try:
  plain_text = bytes.fromhex(hex)
  cipher = AES.new(key, AES.MODE_CBC, iv)
  cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
  return cipher_text.hex()
 except: return ""

async def get_token(acc, session):
 try:
  async with session.get("https://ff-community-api.vercel.app/oauth/guest:token?data={}".format(acc)) as response:
   if response.status == 200:
    data = await response.json()
    return data.get("8")
   return None
 except: return None

async def refresh_tokens():
 global tokens
 try:
  accounts = get_next_accounts(115)
  if accounts:
   timeout = aiohttp.ClientTimeout(total=30)
   async with aiohttp.ClientSession(timeout=timeout) as session:
    tasks = [get_token("{}:{}".format(uid, password), session) for uid, password in accounts]
    new_tokens = await asyncio.gather(*tasks)
    valid_tokens = [token for token in new_tokens if isinstance(token, str) and token]
    with tokens_lock:
     tokens = {token: 0 for token in valid_tokens}
 except:
  with tokens_lock:
   tokens = {}
 threading.Timer(12345, lambda: asyncio.run(refresh_tokens())).start()

async def clean_and_replace_tokens():
 global tokens
 tokens_to_remove = []
 with tokens_lock:
  tokens_to_remove = [token for token, count in tokens.items() if count >= 27]
 if not tokens_to_remove: return
 accounts = get_next_accounts(len(tokens_to_remove) + 5)
 if accounts:
  try:
   timeout = aiohttp.ClientTimeout(total=30)
   async with aiohttp.ClientSession(timeout=timeout) as session:
    tasks = [get_token("{}:{}".format(uid, password), session) for uid, password in accounts]
    new_tokens = await asyncio.gather(*tasks, return_exceptions=True)
    valid_new_tokens = [token for token in new_tokens if isinstance(token, str) and token]

    with tokens_lock:
     for old_token in tokens_to_remove:
      if old_token in tokens:
       del tokens[old_token]

     for new_token in valid_new_tokens:
      tokens[new_token] = 0
  except:
   with tokens_lock:
    for old_token in tokens_to_remove:
     if old_token in tokens:
      del tokens[old_token]

async def generate_additional_tokens(needed_tokens):
 try:
  accounts = get_next_accounts(needed_tokens + 10)
  if not accounts:
   return []
  timeout = aiohttp.ClientTimeout(total=30)
  async with aiohttp.ClientSession(timeout=timeout) as session:
   tasks = [get_token("{}:{}".format(uid, password), session) for uid, password in accounts]
   new_tokens = await asyncio.gather(*tasks, return_exceptions=True)
   valid_tokens = [token for token in new_tokens if isinstance(token, str) and token]
   with tokens_lock:
    for token in valid_tokens:
     tokens[token] = 0
   return valid_tokens
 except: return []

async def refresh_token():
 global gringay
 try:
  timeout = aiohttp.ClientTimeout(total=30)
  async with aiohttp.ClientSession(timeout=timeout) as s:
   gringay = await get_token("3967101993:GRINGOh5TARmcRmm48ZaQN", s)
 except: pass
 threading.Timer(13500, lambda: asyncio.run(refresh_token())).start()


async def LikesProfile(payload, session, token):
 try:
  url = "https://clientbp.ggblueshark.com/LikeProfile"
  headers = {
   "ReleaseVersion": "OB50",
   "X-GA": "v1 1",
   "Authorization": "Bearer {}".format(token),
   "Host": "clientbp.ggblueshark.com"
  }
  async with session.post(url, headers=headers, data=payload, timeout=10) as res:
   return res.status == 200
 except: return False

async def GetPlayerPersonalShow(payload, session):
 global gringay
 try:
  url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
  headers = {
   "ReleaseVersion": "OB50",
   "X-GA": "v1 1",
   "Authorization": "Bearer {}".format(gringay),
   "Host": "clientbp.ggblueshark.com"
  }
  async with session.post(url, headers=headers, data=payload) as res:
   if res.status == 200:
     r = await res.read()
     return json.loads(protobuf_dec(r.hex()))
   return None
 except: return None

def add_token_usage(_token):
 with tokens_lock:
  for token in _token:
   if token in tokens:
    tokens[token] += 1


async def sendLikes(uid):
 global used_uids, tokens
 today = datetime.now().date()
 with uids_:
  if uid in used_uids and used_uids[uid] == today:
   return {"message": "acc này max likes hôm nay r th quỉ"}, 200
 with tokens_lock:
  available_tokens = {k: v for k, v in tokens.items() if v < 27}
  token_list = list(available_tokens.keys())

 if len(token_list) < 115:
  needed_tokens = 115 - len(token_list)
  new_tokens = await generate_additional_tokens(needed_tokens)
  with tokens_lock:
   available_tokens = {k: v for k, v in tokens.items() if v < 27}
   token_list = list(available_tokens.keys())
  if len(token_list) < 100:
   return {"message": "{}".format(len(token_list))}, 200

 _tokens = token_list[:115]
 packet = create_protobuf_packet({1: int(uid), 2: 1}).hex()
 encrypted_packet = encrypt_api(packet)
 if not encrypted_packet: "null", 201
 payload = bytes.fromhex(encrypted_packet)

 timeout = aiohttp.ClientTimeout(total=0x5)
 async with aiohttp.ClientSession(timeout=timeout) as session:
  InfoBefore = await GetPlayerPersonalShow(payload, session)
  if not InfoBefore or "1" not in InfoBefore or "21" not in InfoBefore["1"]:
   return {"message": "Account does not exist"}, 200

  LikesBefore = int(InfoBefore["1"]["21"])
  start_time = time.time()

  tasks = [LikesProfile(payload, session, token) for token in _tokens]
  await asyncio.gather(*tasks)
  with uids_: used_uids[uid] = today

  InfoAfter = await GetPlayerPersonalShow(payload, session)
  if not InfoAfter or "1" not in InfoAfter or "21" not in InfoAfter["1"]:
   return "null", 201

  LikesAfter = int(InfoAfter["1"]["21"])
  LikesAdded = LikesAfter - LikesBefore
  add_token_usage(token_list)
  asyncio.create_task(clean_and_replace_tokens())

  if LikesAdded <= 5:
   return {"message": "Account Id '{}' with name '{}' has reached max likes today, try again tomorrow !".format(InfoBefore["1"]["1"], InfoBefore["1"]["3"])}, 200
  end_time = time.time()
  return {
   "result": {
    "User Info": {
     "Account UID": InfoBefore["1"]["1"],
     "Account Name": InfoBefore["1"]["3"],
     "Account Region": InfoBefore["1"]["5"],
     "Account Level": InfoBefore["1"]["6"],
     "Account Likes": InfoBefore["1"]["21"]
    },
    "Likes Info": {
     "Likes Before": LikesBefore,
     "Likes After": LikesBefore + LikesAdded,
     "Likes Added": LikesAdded,
     "Likes start of day": max(0, LikesBefore + LikesAdded - 100),
    },
    "API": {
     "speeds": "{:.1f}s".format(end_time - start_time),
     "success": True,
    }
   }
  }, 200


def reset_uids():
 global used_uids, account_index
 with uids_:
  used_uids = {}
  account_index = 0

def schedule_reset():
 now = datetime.now(timezone.utc)
 next_reset = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc) + timedelta(days=1)
 delta_seconds = (next_reset - now).total_seconds()
 threading.Timer(delta_seconds, lambda: [reset_uids(), schedule_reset()]).start()


@app.route("/", methods=["GET"])
def start(): return "ok"

@app.route("/likes", methods=["GET"])
def FF_LIKES():
 uid = request.args.get("uid")
 if not uid: return 'thiêú id kìa th quỉ'
 try: uid = str(uid).strip()
 except: return '?'
 try:
  loop = asyncio.new_event_loop()
  asyncio.set_event_loop(loop)
  result = loop.run_until_complete(sendLikes(uid))
  loop.close()
  return jsonify(result[0]), result[1]
 except Exception as e: return e


if __name__ == "__main__":
 load_accounts()
 def gay():
  asyncio.run(refresh_tokens())
  asyncio.run(refresh_token())
 threading.Thread(target=gay, daemon=True).start()
 schedule_reset()
 app.run(host="0.0.0.0", port=5000, threaded=True)