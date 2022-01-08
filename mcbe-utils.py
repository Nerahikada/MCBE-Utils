import argparse
from concurrent import futures
import random
import re
import socket
import struct
import time
import traceback

RAKLIB_MAGIC = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
MCPE_PONG = b'MCPE;'


def log(text, v=False):
	if v and not verbose:
		return
	print(text)


def clean_formated_text(string):
	return re.sub(r'§[0-9a-gk-or]', '', string)


def ping():
	while True:
		response = ping_to(target_ip, target_port)
		if response['time'] is None:
			log(f'{target_ip}:{target_port} > offline')
		else:
			ping_ms = response['time']
			player_count = response['player_count']
			max_player_count = response['max_player_count']
			log(f'{target_ip}:{target_port} > players=({player_count}/{max_player_count}) time={ping_ms}')
			log('\t\tname="' + clean_formated_text(response['server_name']) + '" level="' + response['level_name'] + '" id=' + response['server_id'], True)
			time.sleep(1)

def ping_to(ip, port=19132):
	status = {
		'ip': None,
		'port': None,
		'time': None,

		'server_name': None,
		'protocol_version': None,
		'minecraft_version': None,
		'player_count': None,
		'max_player_count': None,
		'server_id': None,
		'level_name': None,
		'gamemode': None
		#'difficulity': None	# maybe???
	}

	try:
		start_ms = int(round(time.time() * 1000))

		payload = b'\x01' + struct.pack('>Q', random.randint(0, 2147483647)) + RAKLIB_MAGIC + struct.pack('>Q', 0)
		s.sendto(payload, (ip, port))

		data, addr = s.recvfrom(2048)

		if RAKLIB_MAGIC in data and MCPE_PONG in data:
			ping_ms = int(round(time.time() * 1000)) - start_ms
			split_data = data.split(MCPE_PONG)[1].decode('utf-8').split(';')

			status['ip'] = addr[0]
			status['port'] = addr[1]
			status['time'] = ping_ms

			status['server_name'] = split_data[0]
			status['protocol_version'] = split_data[1]
			status['minecraft_version'] = split_data[2]
			status['player_count'] = split_data[3]
			status['max_player_count'] = split_data[4]
			status['server_id'] = split_data[5]
			status['level_name'] = split_data[6]
			status['gamemode'] = split_data[7]

	except socket.timeout as e:
		pass

	except IndexError as e:
		print(split_data)
		raise e

	return status


def scan():
	with futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
		for future in futures.as_completed([executor.submit(ping_to, target_ip, x) for x in range(0, 65535 + 1)]):
			response = future.result()
			if not response['time'] is None:
				server_name = clean_formated_text(response['server_name'])
				player_count = response['player_count']
				max_player_count = response['max_player_count']
				log(target_ip + ':' + str(response['port']) + f' {server_name} ({player_count}/{max_player_count})')


def query():
	result = query_to(target_ip, target_port)
	for key, value in result.items():
		print(key, value)

def query_to(ip, port):
	try:
		session_id = random.randint(0, 2147483647)
		s.sendto(b'\xfe\xfd' + b'\x09' + struct.pack('i', session_id), (ip, port))

		data, addr = s.recvfrom(2048)

		tmp = struct.unpack_from('=ci', data)
		if tmp[0] != b'\x09' or tmp[1] != session_id:
			return None

		token = int(data[5:].rstrip(b'\x00').decode('utf-8'))
		
		session_id = random.randint(0, 2147483647)

		s.sendto((
			b'\xfe\xfd' + b'\x00' + struct.pack('i', session_id) +
			struct.pack('!i', token) +
			b'\xff\xff\xff\x01'
			), (ip, port))

		data, addr = s.recvfrom(2048)

		tmp = struct.unpack_from('=ci', data)
		if tmp[0] != b'\x00' or tmp[1] != session_id:
			return None

		response = data[5:].split(b'\x00\x01')

		data = response[0].split(b'\x00')
		byte_query_result = dict(zip(data[0::2], data[1::2]))
		
		data = response[1].split(b'\x00\x00')
		byte_query_result[data[0]] = data[1].split(b'\x00')
		if data[1] == b'\x00':
			byte_query_result[data[0]] = []

		query_result = {}
		for key, value in byte_query_result.items():
			try:
				if type(value) is list:
					for index, item in enumerate(value):
						value[index] = item.decode('utf-8')
					query_result[key.decode('utf-8')] = value
				else:
					query_result[key.decode('utf-8')] = value.decode('utf-8')
			except:
				query_result[key.decode('utf-8')] = value

		return query_result

	except socket.timeout as e:
		return None


def init_socket():
	global s
	global timeout
	log('Creating socket...', True)
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.setblocking(False)
	s.settimeout(timeout)

	while True:
		try:
			random_port = random.randint(49152, 65535)
			log(f'Binding to port {random_port}...', True)
			s.bind(('', random_port))
			break
		except Exception as e:
			log('Socket binding failed. Retrying...', True)
	log('Socket binding successful', True)

def main():
	global target_ip
	global target_port
	global thread_count
	global verbose
	global timeout

	log('\n[[[    Utility Tools for MCBE  ;D    ]]]\n')

	parser = argparse.ArgumentParser()
	parser.add_argument('mode', help='choose tools', choices=['ping', 'scan', 'query'])
	parser.add_argument('address', help='ping a given ip address')
	parser.add_argument('-p', '--port', help='set port', type=int, default=19132)
	parser.add_argument('-t', '--thread', help='set max thread count', type=int, default=64)
	parser.add_argument('--verbose', help='increase output verbosity', action='store_true')
	parser.add_argument('--timeout', help='socket timeout', type=int, default=4)
	args = parser.parse_args()

	target_ip = args.address
	target_port = args.port
	thread_count = args.thread
	verbose = args.verbose
	timeout = args.timeout

	if ':' in target_ip:
		splited = target_ip.split(':')
		target_ip = splited[0]
		target_port = int(splited[1])

	init_socket()

	globals()[args.mode]()


if __name__ == "__main__":
	main()
