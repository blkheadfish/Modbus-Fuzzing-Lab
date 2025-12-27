console.log("Monitoring...");
const {spawn} = require('child_process');
const express = require('express');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const path = require('path');

let simulator = null;
let currentConfig = {
	protectLength: false,
	protectFuncCode: false,
	protectPayload: false,
	protectMismatch: false
};

function startSimulator() {
	if (simulator) simulator.kill();

	// 开启 IPC 频道以便给子进程发消息
	simulator = spawn('node', [path.join(__dirname, 'simulator.js')], {
		stdio: ['inherit', 'pipe', 'pipe', 'ipc']
	});

	// 启动后立即同步当前的防护配置
	simulator.send({type: 'UPDATE_CONFIG', data: currentConfig});

	let lastPacketRaw = null;
	simulator.stdout.on('data', (data) => {
		data.toString().split(/\r?\n/).forEach(line => {
			if (line.startsWith('PACKET:')) {
				const raw = line.replace('PACKET:', '').trim();
				io.emit('newPacket', { time: new Date().toLocaleTimeString().split(' ')[0], raw });
			} else if (line.startsWith('SYSTEM:READY')) {
				const pid = line.split(':')[2];
				// 推送 RUNNING 状态,带上 PID
				io.emit('statusUpdate', { status: "RUNNING", pid: pid });
			} else if (line.startsWith('LOG:Blocked')) {
				io.emit('archiveEvent', {
					type: 'BLOCKED',
					msg: line.replace('LOG:', ''),
					pkt: { time: new Date().toLocaleTimeString().split(' ')[0], raw: lastPacketRaw }
				});
				io.emit('log', line.replace('LOG:', ''));
			}
			// 检测到 CRASH 时
			else if (line.startsWith('CRASH_REASON:')) {
				io.emit('archiveEvent', {
					type: 'FATAL',
					msg: line.replace('CRASH_REASON:', ''),
					pkt: { time: new Date().toLocaleTimeString().split(' ')[0], raw: lastPacketRaw }
				});
				io.emit('log', line.replace('CRASH_REASON:', ''));
			}
		});
	});

	simulator.on('exit', (code) => {
		if (code !== null) io.emit('statusUpdate', {status: "CRASHED"});
	});
}

io.on('connection', (socket) => {
	socket.on('restart', () => startSimulator());

	// 监听网页发来的防护切换请求
	socket.on('toggleProtect', (config) => {
		currentConfig = config;
		if (simulator && simulator.connected) {
			simulator.send({type: 'UPDATE_CONFIG', data: currentConfig});
		}
	});
});

startSimulator();
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
http.listen(3000);
console.log('Listening on port 3000');
