// simulator.js
const net = require('net');
const PORT = 5020;


//  模拟 Modbus 寄存器数据
const registers = new Uint16Array(1000);
for (let i = 0; i < 1000; i++) {
	registers[i] = i * 10;
}

// 防御配置状态
let config = {
	protectLength: false, //长度攻击防护
	protectFuncCode: false, //功能码拦截
	protectPayload: false, //超大负载限制
	protectFormat: false, //格式匹配校验
	protectBoundary: false //业务逻辑边界
};

process.on('message', (msg) => {
	if (msg.type === 'UPDATE_CONFIG') config = msg.data;
});

const server = net.createServer((socket) => {
	socket.on('data', (data) => {
		// 立即输出原始报文，用于前端数据流展示
		process.stdout.write(`PACKET:${data.toString('hex').toUpperCase()}\n`);

		// 对于功能码为0x3来说，如果发出的包的payload长度大于4则为payload异常
		if (data.length - 8 > 4) {
			if (config.protectPayload) {
				process.stdout.write("LOG:Blocked Payload Overflow Attack (Protection ON)\n");
				return;
			} else {
				process.stdout.write("CRASH_REASON:FATAL - Heap Exhaustion by oversized payload\n");
				process.exit(1);
			}
		}

		// 包长不足以支撑最基本的 MBAP+Func 结构
		if (data.length < 8) {
			if (config.protectFormat) {
				process.stdout.write("LOG:Blocked Malformed Format Attack (Protection ON)\n");
				return;
			} else {
				process.stdout.write("CRASH_REASON:FATAL - Protocol structure damaged (Format Mismatch)\n");
				process.exit(1);
			}
		}

		// 检查 MBAP 头部声明长度与实际接收长度是否一致
		const declaredLen = data.readUInt16BE(4);
		const actualLenAfterUnit = data.length - 6; // 减去前6个字节(TransID + ProtoID + LenField)

		if (declaredLen !== actualLenAfterUnit) {
			if (config.protectLength) {
				process.stdout.write(`LOG:Blocked Length Mismatch: Declared ${declaredLen}, Actual ${actualLenAfterUnit}\n`);
				return;
			} else {
				process.stdout.write(`CRASH_REASON:FATAL - MBAP Length Corruption (Buffer Underflow)\n`);
				process.exit(1);
			}
		}

		// 功能码
		const funcCode = data[7];
		if (funcCode !== 0x03) {
			if (config.protectFuncCode) {
				process.stdout.write(`LOG:Blocked Illegal Function Code: 0x${funcCode.toString(16).toUpperCase()}\n`);
				return;
			} else {
				process.stdout.write(`CRASH_REASON:FATAL - Unauthorized Function Code 0x${funcCode.toString(16).toUpperCase()}\n`);
				process.exit(1);
			}
		}

		// 边界检查
		// 只有当数据长度足够解析 Addr 和 Qty 时才进行
		let startAddr = 0;
		let quantity = 0;

		if (data.length >= 12) {
			startAddr = data.readUInt16BE(8);
			quantity = data.readUInt16BE(10);

			// 模拟寄存器范围为 0-1000, 且数量不能为 0 或 超过 125
			if (quantity === 0 || quantity > 125 || (startAddr + quantity) > 1000) {
				if (config.protectBoundary) {
					process.stdout.write(`LOG:Blocked Boundary Attack: Addr ${startAddr}, Qty ${quantity}\n`);
					return; // 拒绝服务
				} else {
					process.stdout.write(`CRASH_REASON:FATAL - Out of Range Access: Addr ${startAddr}, Qty ${quantity}\n`);
					process.exit(1);
				}
			}
		} else {
			// 如果长度不够解析 Addr/Qty，但在前面Length Check未开启时可能漏进来
			return;
		}

		try {
			// 计算响应需要的字节数
			const byteCount = quantity * 2;
			// 响应包总长 = MBAP头(7字节: TransId[2]+Proto[2]+Len[2]+Unit[1]) + Func[1] + ByteCount[1] + Data[N]
			// 注意：MBAP中的 Length 字段值 = UnitId(1) + Func(1) + ByteCount(1) + Data(N)
			const mbapLengthVal = 1 + 1 + 1 + byteCount;

			const responseBuffer = Buffer.alloc(6 + mbapLengthVal);

			// Transaction ID (0-1)
			data.copy(responseBuffer, 0, 0, 2);

			// Protocol ID (2-3)
			data.copy(responseBuffer, 2, 2, 4);

			// Length (4-5)
			responseBuffer.writeUInt16BE(mbapLengthVal, 4);

			// Unit ID (6)
			responseBuffer[6] = data[6];

			// Function Code (7)
			responseBuffer[7] = 0x03;

			// Byte Count (8)
			responseBuffer[8] = byteCount;

			for (let i = 0; i < quantity; i++) {
				// 从虚拟寄存器中读取数据
				const val = registers[startAddr + i];
				responseBuffer.writeUInt16BE(val, 9 + (i * 2));
			}

			socket.write(responseBuffer);

		} catch (e) {
			process.stdout.write(`LOG:Internal Simulation Error: ${e.message}\n`);
		}
	});

	socket.on('error', (err) => {
		// 忽略网络错误，防止客户端断开导致崩溃
	});

}).listen(PORT, () => {
	process.stdout.write(`SYSTEM:READY:${process.pid}\n`);
});