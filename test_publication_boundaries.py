"""Portable CSV and single-output publication regressions; offline fixtures only."""
import contextlib
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import node2shell_check as c
class CsvPublicationTests(unittest.TestCase):
    def run_cli(self,*args):
        with contextlib.redirect_stdout(io.StringIO()) as out,contextlib.redirect_stderr(io.StringIO()) as err:
            code=c.main(list(args))
        return code,out.getvalue(),err.getvalue()
    def test_nul_inventory_csv_rejects_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory=Path(directory)/'inventory.json'
            inventory.write_text(json.dumps({'schema_version':1,'runtime':'node','node_version':'24.22.1','label':'example\x00asset'}))
            for mode in ['stdout','new','force']:
                target=Path(directory)/(mode+'.csv');extra=[]
                if mode!='stdout':extra=['--output',str(target)]
                if mode=='force':target.write_text('KEEP');extra+=['--force']
                code,out,err=self.run_cli('--inventory',str(inventory),'--format','csv',*extra)
                self.assertEqual((2,''),(code,out));self.assertNotIn('Traceback',err)
                if mode=='force':self.assertEqual('KEEP',target.read_text())
                else:self.assertFalse(target.exists())
            code,out,_=self.run_cli('--inventory',str(inventory),'--format','json')
            self.assertEqual(0,code);self.assertEqual(1,len(json.loads(out)['results']))
    def test_bare_carriage_return_in_inventory_keeps_one_csv_record(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory=Path(directory)/'inventory.json'
            inventory.write_text(json.dumps({'schema_version':1,'runtime':'node','node_version':'24.22.1','label':'example\r=1+1'}))
            code,out,_=self.run_cli('--inventory',str(inventory),'--format','csv')
            self.assertEqual(0,code)
            rows=list(csv.DictReader(io.StringIO(out,newline='')))
            self.assertEqual(1,len(rows));self.assertNotIn(None,rows[0])
            self.assertTrue(any('\r=1+1' in value for value in rows[0].values()))
    def test_partial_stdout_interrupt_has_one_write_and_exit130(self):
        class Sink:
            calls=0
            def write(self,data):self.calls+=1;raise KeyboardInterrupt
        sink=Sink()
        with contextlib.redirect_stdout(sink),contextlib.redirect_stderr(io.StringIO()):
            escaped=False
            try:code=c.main(['--node-version','24.22.1','--format','json'])
            except KeyboardInterrupt:escaped=True;code=130
        self.assertFalse(escaped,'main must handle its publication interruption')
        self.assertEqual(130,code);self.assertEqual(1,sink.calls)
if __name__=='__main__':unittest.main()
