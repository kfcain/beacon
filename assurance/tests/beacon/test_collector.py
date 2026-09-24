import importlib.util, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('collector',Path(__file__).parents[2]/'collectors'/'aws.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Session:
    def __init__(self,deny=False,wrong=False): self.deny=deny; self.wrong=wrong
    def get_partition_for_region(self,r): return 'aws-us-gov'
    def client(self,service,region_name,config=None):
        outer=self
        class Client:
            def get_caller_identity(self): return {'Account':'222222222222' if outer.wrong else '111111111111','Arn':'arn:aws-us-gov:sts::111111111111:assumed-role/test/session'}
            def get_ebs_encryption_by_default(self):
                if outer.deny and region_name=='us-gov-east-1': raise RuntimeError('denied')
                return {'EbsEncryptionByDefault':True}
        return Client()
class CollectorTests(unittest.TestCase):
    def setUp(self): self.scope=[{'partition':'aws-us-gov','account':'111111111111','region':r} for r in ['us-gov-west-1','us-gov-east-1']]
    def test_complete(self):
        r=m.collect(Session(),self.scope,'ENC-01'); self.assertEqual(r['mode'],'live'); self.assertTrue(all(x['collectionStatus']=='complete' for x in r['observations']))
    def test_partial_preserved(self):
        r=m.collect(Session(deny=True),self.scope,'ENC-01');self.assertEqual([x['collectionStatus'] for x in r['observations']],['complete','error']);self.assertIn('raw',r['observations'][0])
    def test_identity_mismatch(self):
        r=m.collect(Session(wrong=True),self.scope,'ENC-01');self.assertTrue(all(x['collectionStatus']=='error' for x in r['observations']))
    def test_duplicate_rejected(self):
        with self.assertRaises(ValueError):m.collect(Session(),[self.scope[0]]*2,'ENC-01')
if __name__=='__main__':unittest.main()
