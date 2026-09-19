import tempfile
from pathlib import Path
import socket
import threading
import time
import unittest
import sentinel as s

class Tests(unittest.TestCase):
    def events(self):
        return [dict(s.parse(m.encode(), '127.0.0.1', 'tcp', i), id=i+1) for i,m in enumerate(s.demo_messages())]

    def test_detection_and_health(self):
        result = s.analyze(self.events(), ['web-01','fw-01','db-01'], now=10)
        self.assertEqual([f['rule'] for f in result['findings']], ['SSH-001','SSH-002'])
        self.assertEqual(result['findings'][1]['evidence'], [3,4,5,6,7,8,9])
        self.assertEqual(result['health'][2]['state'], 'never seen')
        self.assertEqual(s.analyze(self.events(), ['web-01'], now=200)['health'][0]['state'], 'silent')

    def test_window_and_scope(self):
        for field,value in [('host','other'),('app','firewall'),('message','Accepted password for bob from 198.51.100.23')]:
            events=self.events()
            events[-1][field]=value
            self.assertEqual(len(s.analyze(events,[])['findings']),1)
        events=self.events()
        events[-1]['received']=100
        self.assertEqual(len(s.analyze(events,[])['findings']),1)
        for i,e in enumerate(events):
            e['received']=i*61
        self.assertEqual(s.analyze(events,[])['findings'],[])

    def test_parser(self):
        self.assertEqual(self.events()[2]['severity'],4)
        for payload in [b'garbage',b'<999>1 - h a - - - msg',b'<84>1 - h a - - [meta x="y"] msg']:
            e=s.parse(payload,'127.0.0.1','udp')
            self.assertFalse(e['parsed'])
            self.assertEqual(e['raw'],payload.decode())
        self.assertTrue(s.parse(b'<34>Oct 11 22:14:15 host sshd[12]: hello','127.0.0.1','udp')['parsed'])

    def test_html_escaping(self):
        events=self.events()
        events[0]['message']='<script>alert(1)</script>'
        with tempfile.TemporaryDirectory() as out:
            s.write_report(events,s.analyze(events,[]),out)
            text=(Path(out)/'report.html').read_text()
            self.assertNotIn('<script>alert(1)',text)
            self.assertIn('&lt;script&gt;',text)

    def test_network_and_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'events.db')
            store=s.Store(path)
            pair=s.servers(store,'127.0.0.1',0)
            threads=[threading.Thread(target=x.serve_forever) for x in pair]
            for t in threads: t.start()
            port=pair[0].server_address[1]
            try:
                messages=s.demo_messages()
                s.send('127.0.0.1',port,'tcp',messages)
                s.send('127.0.0.1',port,'udp',messages[:1])
                payload=messages[0].encode()
                with socket.create_connection(('127.0.0.1',port)) as sock:
                    frame=str(len(payload)).encode()+b' '+payload
                    sock.sendall(frame[:8])
                    sock.sendall(frame[8:])
                    sock.sendall(payload+b'\n')
                deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    events=s.read_events(path)
                    if len(events)==12: break
                    time.sleep(.02)
                self.assertEqual(len(events),12)
                self.assertEqual({e['transport'] for e in events},{'tcp','udp'})
                self.assertEqual(len(s.analyze(events,[])['findings']),2)
            finally:
                for x in pair:
                    x.shutdown()
                    x.server_close()
                for t in threads: t.join()
                store.close()
            reopened=s.Store(path)
            self.assertEqual(len(s.read_events(path)),12)
            reopened.close()

if __name__=='__main__': unittest.main()
