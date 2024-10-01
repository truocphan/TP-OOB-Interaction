import os, sys, random, uuid, base64, time, datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests
import argparse, signal
import json_duplicate_keys as jdks
import TP_sendNotify


def handler(signum, stack_frame):
	res = input("\n \x1b[0;31mDo you really want to exit? [Y/n]\x1b[0m ")
	if res in ["y", "Y", ""]: exit()

signal.signal(signal.SIGINT, handler)


def generate_random_string():
	charsets = "abcdefghijklmnopqrstuvwxyz"
	return "".join(random.choice(charsets) for _ in range(33))


def generate_registration_params():
	# Generate RSA key pair
	key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)
    
	# Export the public key in PEM format
	publicKey = key.public_key().public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	).decode("utf-8").strip()

	# Export the private key in PKCS#8 format
	privateKey = key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	).decode("utf-8").strip()

	# Generate correlation ID and secret
	collaboratorServer = generate_random_string()
	correlationId = collaboratorServer[:20]
	secretKey = str(uuid.uuid4())

	oastServer = random.choice(["oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"])
	collaboratorServer = "{collaboratorServer}.{oastServer}".format(collaboratorServer=collaboratorServer, oastServer=oastServer)

	return oastServer, collaboratorServer, publicKey, privateKey, correlationId, secretKey


def register():
	while True:
		try:
			oastServer, collaboratorServer, publicKey, privateKey, correlationId, secretKey = generate_registration_params()

			res = requests.post("https://{oastServer}/register".format(oastServer=oastServer),
				json = {
					"public-key": base64.b64encode(publicKey.encode("utf-8")).decode("utf-8"),
					"secret-key": secretKey,
					"correlation-id": correlationId
				}
			)

			if res.status_code == 200 and res.json()["message"] == "registration successful":
				jdks.JSON_DUPLICATE_KEYS({
					"oastServer": oastServer,
					"collaboratorServer": collaboratorServer,
					"correlationId": correlationId,
					"secretKey": base64.b64encode(secretKey.encode("utf-8")).decode("utf-8"),
					"privateKey": base64.b64encode(privateKey.encode("utf-8")).decode("utf-8"),
					"publicKey": base64.b64encode(publicKey.encode("utf-8")).decode("utf-8")
				}).dump(os.path.join(os.path.expanduser("~"), ".TPConfig", "TP-OOB-Interaction", "OOB-Interaction.json"), indent=4)
				break
		except Exception as e:
			print("[\x1b[0;34m"+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"\x1b[0m]" + " \x1b[0;31m"+str(e)+"\x1b[0m")
		time.sleep(5)


def decryptAESKey(encryptedAESkey, privateKey):
	# Load the private key from the provided PKCS#8 string
	private_key = serialization.load_pem_private_key(
		privateKey.encode(), 
		password=None, 
		backend=default_backend()
	)

	# Decode the base64 encoded AES key
	aes_key_bytes = base64.b64decode(encryptedAESkey)

	# Decrypt the AES key using the RSA private key
	decrypted_key = private_key.decrypt(
		aes_key_bytes,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	return decrypted_key


def decryptData(encryptedData, AESkey):
	IV = base64.b64decode(encryptedData)[:16]
	
	cipher = Cipher(algorithms.AES(AESkey), modes.CFB(IV), backend=default_backend())
	decryptor = cipher.decryptor()

	decrypted_data = decryptor.update(base64.b64decode(encryptedData)[16:]) + decryptor.finalize()
	return decrypted_data.decode("utf-8")


def poll(oastServer, correlationId, secretKey, privateKey):
	isOK = False
	try:
		res = requests.get("https://{oastServer}/poll?id={correlationId}&secret={secretKey}".format(oastServer=oastServer, correlationId=correlationId, secretKey=secretKey))
		if res.status_code == 200:
			AESkey = decryptAESKey(res.json()["aes_key"], privateKey)
			isOK = True
			if res.json()["data"] != None:
				for encryptedData in res.json()["data"]:
					data = jdks.loads(decryptData(encryptedData, AESkey))
					print("[\x1b[0;34m"+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"\x1b[0m]" + "[\x1b[0;33m"+data.get("full-id")+"."+oastServer+"\x1b[0m]" + " Received \x1b[0;33m{protocol}\x1b[0m interaction\x1b[0;33m{q_type}\x1b[0m from \x1b[0;33m{remote_address}\x1b[0m at \x1b[0;33m{timestamp}\x1b[0m".format(protocol=data.get("protocol").upper(), q_type=(" ("+data.get("q-type")+")" if data.get("q-type")!="JSON_DUPLICATE_KEYS_ERROR" else ""), remote_address=data.get("remote-address"), timestamp=data.get("timestamp")))

					if args.discord_bot:
						TP_sendNotify.toDiscord(args.discord_bot, "### [{collaboratorServer}] Received {protocol} interaction{q_type} from {remote_address} at {timestamp}\n```\n{raw_request}\n```".format(collaboratorServer=data.get("full-id")+"."+oastServer, protocol=data.get("protocol").upper(), q_type=(" ("+data.get("q-type")+")" if data.get("q-type")!="JSON_DUPLICATE_KEYS_ERROR" else ""), remote_address=data.get("remote-address"), timestamp=data.get("timestamp"), raw_request=data.get("raw-request").replace("```","``ˋ")), SidebarColor=0xffff00)

					if args.telegram_bot:
						TP_sendNotify.toTelegram(args.telegram_bot, "*[{collaboratorServer}] Received {protocol} interaction{q_type} from {remote_address} at {timestamp}*\n```\n{raw_request}\n```".format(collaboratorServer=data.get("full-id")+"."+oastServer, protocol=data.get("protocol").upper(), q_type=(" ("+data.get("q-type")+")" if data.get("q-type")!="JSON_DUPLICATE_KEYS_ERROR" else ""), remote_address=data.get("remote-address"), timestamp=data.get("timestamp"), raw_request=data.get("raw-request").replace("```","``ˋ")), MessageFormat="Markdown")

					if args.slack_bot:
						TP_sendNotify.toSlack(args.slack_bot, "*[{collaboratorServer}] Received {protocol} interaction{q_type} from {remote_address} at {timestamp}*\n```\n{raw_request}\n```".format(collaboratorServer=data.get("full-id")+"."+oastServer, protocol=data.get("protocol").upper(), q_type=(" ("+data.get("q-type")+")" if data.get("q-type")!="JSON_DUPLICATE_KEYS_ERROR" else ""), remote_address=data.get("remote-address"), timestamp=data.get("timestamp"), raw_request=data.get("raw-request").replace("```","``ˋ")))
	except Exception as e:
		print("[\x1b[0;34m"+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"\x1b[0m]" + " \x1b[0;31m"+str(e)+"\x1b[0m")
	return isOK


def Update(): os.system("{} -W ignore -m pip install TP-OOB-Interaction --upgrade".format(sys.executable))


def main():
	print("\x1b[0;33m")
	print(r"  _____ ____     ___   ___  ____       ___       _                      _   _")
	print(r" |_   _|  _ \   / _ \ / _ \| __ )     |_ _|_ __ | |_ ___ _ __ __ _  ___| |_(_) ___  _ __")
	print(r"   | | | |_) | | | | | | | |  _ \ _____| || '_ \| __/ _ \ '__/ _\`|/ __| __| |/ _ \| '_ \ ")
	print(r"   | | |  __/  | |_| | |_| | |_) |_____| || | | | ||  __/ | | (_| | (__| |_| | (_) | | | |")
	print(r"   |_| |_|      \___/ \___/|____/     |___|_| |_|\__\___|_|  \__,_|\___|\__|_|\___/|_| |_|")
	print("\x1b[0m")
	print("                                \x1b[0;34mv2024.10.1\x1b[0m by \x1b[0;31mTP Cyber Security (@TPCyberSec)\x1b[0m")
	print("\x1b[0m")

	global args, InteractConfig
	parser = argparse.ArgumentParser(prog="TP-OOB-Interaction")
	parser.add_argument("--discord-bot", metavar="BOT_NAME", type=str, help="Use the BOT \"BOT_NAME\" to send OOB interactions to Discord")
	parser.add_argument("--telegram-bot", metavar="BOT_NAME", type=str, help="Use the BOT \"BOT_NAME\" to send OOB interactions to Telegram")
	parser.add_argument("--slack-bot", metavar="BOT_NAME", type=str, help="Use the BOT \"BOT_NAME\" to send OOB interactions to Slack")
	parser.add_argument("--update", action="store_true", help="Update TP-OOB-Interaction to the latest version")
	args = parser.parse_args()

	if args.update: Update()
	else:
		if not os.path.isfile(os.path.join(os.path.expanduser("~"), ".TPConfig", "TP-OOB-Interaction", "OOB-Interaction.json")):
			if not os.path.isdir(os.path.join(os.path.expanduser("~"), ".TPConfig", "TP-OOB-Interaction")):
				os.makedirs(os.path.join(os.path.expanduser("~"), ".TPConfig", "TP-OOB-Interaction"))
			register()


		while True:
			InteractConfig = jdks.load(os.path.join(os.path.expanduser("~"), ".TPConfig", "TP-OOB-Interaction", "OOB-Interaction.json"))

			if type(InteractConfig) == jdks.JSON_DUPLICATE_KEYS:
				if poll(InteractConfig.get("oastServer"), InteractConfig.get("correlationId"), base64.b64decode(InteractConfig.get("secretKey")).decode("utf-8"), base64.b64decode(InteractConfig.get("privateKey")).decode("utf-8")): break
				else:
					res = requests.post("https://{oastServer}/register".format(oastServer=InteractConfig.get("oastServer")),
						json = {
							"public-key": InteractConfig.get("publicKey"),
							"secret-key": base64.b64decode(InteractConfig.get("secretKey")).decode("utf-8"),
							"correlation-id": InteractConfig.get("correlationId")
						}
					)
					if res.status_code == 200 and res.json()["message"] == "registration successful": break
			register()


		if args.discord_bot:
			TP_sendNotify.toDiscord(args.discord_bot, "**Collaborator Server:** {collaboratorServer}\n```\n{InteractConfig}\n```".format(collaboratorServer=InteractConfig.get("collaboratorServer"), InteractConfig=InteractConfig.dumps(indent=4)), SidebarColor=0x00ccff)

		if args.telegram_bot:
			TP_sendNotify.toTelegram(args.telegram_bot, "*Collaborator Server:* {collaboratorServer}\n```\n{InteractConfig}\n```".format(collaboratorServer=InteractConfig.get("collaboratorServer"), InteractConfig=InteractConfig.dumps(indent=4)), MessageFormat="Markdown")

		if args.slack_bot:
			TP_sendNotify.toSlack(args.slack_bot, "*Collaborator Server:* {collaboratorServer}\n```\n{InteractConfig}\n```".format(collaboratorServer=InteractConfig.get("collaboratorServer"), InteractConfig=InteractConfig.dumps(indent=4)))


		print("[\x1b[0;34m"+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"\x1b[0m]" + " Collaborator Server: \x1b[0;31m{collaboratorServer}\x1b[0m".format(collaboratorServer=InteractConfig.get("collaboratorServer")))

		while True:
			poll(InteractConfig.get("oastServer"), InteractConfig.get("correlationId"), base64.b64decode(InteractConfig.get("secretKey")).decode("utf-8"), base64.b64decode(InteractConfig.get("privateKey")).decode("utf-8"))
			time.sleep(1)


if __name__ == "__main__":
	main()