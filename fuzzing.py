import argparse
import warnings

warnings.filterwarnings('ignore')
from boofuzz import *

import os


def check_target_status(target, fuzzer, data_edge, *args, **kwargs):
	"""
	回调函数：在每个测试用例发送后检查目标机状态
	"""
	try:
		if not target.proc_keep_alive():
			print(f"\n[!] Crashed!")
			print(f"[!] Crashed ID: {fuzzer.total_num_mutations}")
			os._exit(1)
	except Exception as e:
		print(f"\n[!] Can not Connected target: {e}")
		os._exit(1)


def do_attack():
	parser = argparse.ArgumentParser()
	parser.add_argument("--mode", choices=["length", "func", "payload", "format", "bound", "all"], default="length")
	parser.add_argument("--ip", default="127.0.0.1")
	parser.add_argument("--port", type=int, default=502)
	parser.add_argument("--sleep", type=float, default=0.5, help="发包间隔")
	
	args = parser.parse_args()
	
	db_file = f"session_{args.mode}.db"
	if os.path.exists(db_file):
		os.remove(db_file)
	
	session = Session(
		target=Target(connection=TCPSocketConnection(args.ip, args.port)),
		session_filename=db_file,
		sleep_time=args.sleep,
		web_port=1145
	)
	
	# --mode length
	s_initialize("attack_length")
	s_word(0x0001, name="trans_id", fuzzable=False)
	s_word(0x0000, name="proto", fuzzable=False)
	s_word(0x0006, name="length", fuzzable=True)  # 变异长度字段
	s_byte(0x01, name="unit", fuzzable=False)
	s_byte(0x03, name="func", fuzzable=False)
	s_bytes(b"\x00\x01\x00\x01", name="data", fuzzable=False)
	
	# --mode func
	s_initialize("attack_func")
	s_word(0x0001, name="trans_id", fuzzable=False)
	s_word(0x0000, name="proto", fuzzable=False)
	s_word(0x0006, name="length", fuzzable=False, endian='>')
	s_byte(0x01, name="unit", fuzzable=False)
	s_byte(0x03, name="func", fuzzable=True)  # 变异功能码
	s_bytes(b"\x00\x01\x00\x01", name="data", fuzzable=False)
	
	# --mode payload
	s_initialize("attack_payload")
	s_word(0x0001, name="trans_id", fuzzable=False)
	s_word(0x0000, name="proto", fuzzable=False)
	s_word(0x0006, name="length", fuzzable=False, endian=">")
	s_byte(0x01, name="unit", fuzzable=False)
	s_byte(0x03, name="func", fuzzable=False)
	s_bytes(b"\x00\x00\x00\x00", name="data", fuzzable=True)  # 变异payload
	
	# --mode format
	s_initialize("attack_mismatch")
	s_word(0x0001, name="trans_id", fuzzable=False)
	s_word(0x0000, name="proto", fuzzable=False)
	s_word(0x0000, name="length", fuzzable=False)
	s_byte(0x01, name="unit", fuzzable=False)
	s_word(0x0000, name="func")  # 变异结构,让Func字段变为2字节
	s_bytes(b"\x00", name="data", fuzzable=False)
	
	# --mode bound
	s_initialize("attack_bound")
	s_word(0x0001, name="trans_id", fuzzable=False)
	s_word(0x0000, name="proto", fuzzable=False)
	s_word(0x0006, name="length", fuzzable=False, endian=">")
	s_byte(0x01, name="unit", fuzzable=False)
	s_byte(0x03, name="func", fuzzable=False)
	s_word(0x0000, name="address", fuzzable=True)
	s_word(0x0000, name="reg_num", fuzzable=True)
	
	if args.mode == 'length':
		session.connect(s_get("attack_length"))
	elif args.mode == 'func':
		session.connect(s_get("attack_func"))
	elif args.mode == 'payload':
		session.connect(s_get("attack_payload"))
	elif args.mode == 'format':
		session.connect(s_get("attack_mismatch"))
	elif args.mode == 'bound':
		session.connect(s_get("attack_bound"))
	else:
		pass
	# --mode all
	# session.connect(s_get("attack_length"))
	# session.connect(s_get("attack_func"))
	# session.connect(s_get("attack_payload"))
	# session.connect(s_get("attack_mismatch"))
	
	session.fuzz()


if __name__ == '__main__':
	do_attack()
