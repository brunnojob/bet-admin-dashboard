import http.client
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server', ROOT / 'server.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class AppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        app.DB = Path(cls.temp.name) / 'test.sqlite3'
        app.initialize()
        cls.server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temp.cleanup()

    def request(self, path, method='GET', data=None, cookie='', csrf=''):
        conn = http.client.HTTPConnection('127.0.0.1', self.port)
        conn.request(method, '/api/'+path, json.dumps(data) if data is not None else None,
                     {'Host': 'localhost:8000', 'Content-Type': 'application/json', 'Cookie': cookie, 'X-CSRF-Token': csrf})
        response = conn.getresponse()
        status, value, headers = response.status, json.loads(response.read()), dict(response.getheaders())
        conn.close()
        return status, value, headers

    def test_authenticated_crud_and_constraints(self):
        self.assertEqual(self.request('state')[0], 401)
        self.assertEqual(self.request('login', 'POST', {'username':'admingb','password':'wrong'})[0], 401)
        status, login, headers = self.request('login', 'POST', {'username':'admingb','password':'admin'})
        self.assertEqual(status, 200)
        cookie, csrf = headers['Set-Cookie'].split(';')[0], login['csrf']
        call = lambda path, method='GET', data=None: self.request(path, method, data, cookie, csrf)
        self.assertEqual(self.request('sites','POST',{'name':'Site','url':'https://example.com','status':'ativo'},cookie)[0],403)
        status, site, _ = call('sites','POST',{'name':'Site','url':'https://example.com','status':'ativo'})
        self.assertEqual(status,200)
        status, domain, _ = call('domains','POST',{'name':'example.com','site_id':site['id'],'status':'ativo'})
        self.assertEqual(status,200)
        self.assertEqual(call('sites/'+str(site['id']),'DELETE',{})[0],409)
        tx = {'kind':'saque','customer':'Teste','amount':'10.25','status':'pendente','site_id':site['id']}
        status, movement, _ = call('transactions','POST',tx)
        self.assertEqual(status,200)
        self.assertEqual(call('transactions','POST',dict(tx,amount='0.001'))[0],400)
        self.assertEqual(call('transactions','POST',dict(tx,amount='-1'))[0],400)
        self.assertEqual(call('transactions/'+str(movement['id']),'PUT',dict(tx,status='concluido'))[0],200)
        state = call('state')[1]
        self.assertEqual(state['transactions'][0]['amount'],1025)
        self.assertNotIn('password',state['users'][0])
        uid = state['users'][0]['id']
        self.assertEqual(call('users/'+str(uid),'DELETE',{})[0],400)
        self.assertEqual(call('users/'+str(uid),'PUT',{'active':False})[0],400)
        status, admin, _ = call('users','POST',{'username':'operator','password':'secret123','active':True})
        self.assertEqual(status,200)
        self.assertEqual(call('users/'+str(admin['id']),'PUT',{'username':'operator2','password':'newsecret','active':True})[0],200)
        self.assertEqual(self.request('login','POST',{'username':'operator2','password':'newsecret'})[0],200)
        self.assertEqual(call('users/'+str(admin['id']),'DELETE',{})[0],200)
        self.assertEqual(call('transactions/'+str(movement['id']),'DELETE',{})[0],200)
        self.assertEqual(call('domains/'+str(domain['id']),'DELETE',{})[0],200)
        self.assertEqual(call('sites/'+str(site['id']),'DELETE',{})[0],200)
        self.assertGreater(len(call('state')[1]['audit']),5)
        self.assertEqual(call('logout','POST',{})[0],200)
        self.assertEqual(call('state')[0],401)


if __name__ == '__main__':
    unittest.main()
