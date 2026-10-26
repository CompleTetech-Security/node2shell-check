#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Read Node engine declarations from existing npm metadata; never runtime evidence."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys


def inspect(path):
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode): raise ValueError('Expected regular metadata file')
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)|getattr(os,'O_BINARY',0)
    fd=os.open(path,flags)
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno())
        if (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino) or not stat.S_ISREG(opened.st_mode): raise ValueError('Input changed')
        raw=stream.read(4*1024**2+1)
    if len(raw)>4*1024**2: raise ValueError('Metadata byte limit')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise ValueError('Duplicate JSON key')
            result[key]=value
        return result
    data=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    if not isinstance(data,dict):raise ValueError('Expected metadata object')
    pending=[(data,'',0)]
    lock=data.get('lockfileVersion')
    if 'lockfileVersion' in data:
        if type(lock) is not int or lock not in (1,2,3):raise ValueError('Unsupported npm lock version')
        if lock in (2,3):
            packages=data.get('packages')
            if not isinstance(packages,dict):raise ValueError('Expected packages map')
            pending=[]
            for location,entry in packages.items():
                if not isinstance(location,str) or len(location)>512 or '\\' in location or ':' in location or location.startswith('/') or (location and any(p in ('','.','..') for p in location.split('/'))):raise ValueError('Invalid package path')
                pending.append((entry,location,0))
    rows=[];count=0
    while pending:
        entry,location,depth=pending.pop()
        count+=1
        if count>100000 or depth>64 or len(location)>512 or not isinstance(entry,dict):raise ValueError('Metadata structure limit')
        engines=entry.get('engines',{})
        if not isinstance(engines,dict):raise ValueError('Invalid engines metadata')
        if 'node' in engines:
            declaration=engines['node']
            # Only a small semver-range character vocabulary can leave this tool;
            # arbitrary text/URLs/credentials become unknown rather than being echoed.
            supported=isinstance(declaration,str) and len(declaration)<=256 and bool(re.fullmatch(r'[0-9xXvV.*^~<>=|+\- \t]{1,256}',declaration))
            rows.append(dict(package_path=location,declared_node_range=declaration if supported else '',
                             declaration_status='reported_range' if supported else 'unrecognized_or_missing',
                             runtime_version='',runtime_state='unknown',exploitability='not_tested'))
            if len(rows)>10000:raise ValueError('Observation limit')
        if lock==1:
            children=entry.get('dependencies',{})
            if not isinstance(children,dict):raise ValueError('Invalid dependency tree')
            for name,child in children.items():
                if not isinstance(name,str) or not re.fullmatch(r'(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+',name) or any(part in ('.','..') for part in name.split('/')):raise ValueError('Invalid dependency name')
                pending.append((child,location+'/node_modules/'+name if location else 'node_modules/'+name,depth+1))
    return dict(schema_version='node-build-context/1',complete=True,exploitability='not_tested',runtime_version='',
                observations=sorted(rows,key=lambda row:(row['package_path'],row['declared_node_range'])),
                limitations=['Engine declarations are compatibility constraints, not installed/deployed Node versions or runtime feature evidence. Missing observations establish no absence. No registry URLs, scripts or package contents were read or executed.'])


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('--input',type=Path,required=True,help='Existing package.json or npm lock v1/v2/v3; output is metadata JSON on stdout')
    args=parser.parse_args(argv)
    try:
        value=inspect(args.input)
        text=json.dumps(value,ensure_ascii=True,sort_keys=True,indent=2,allow_nan=False)+'\n'
        sys.stdout.write(text);sys.stdout.flush()
        return 0
    except KeyboardInterrupt:return 130
    except (OSError,ValueError,UnicodeError,RecursionError):
        sys.stderr.write('Metadata inspection failed; no runtime version was inferred.\n');return 2


if __name__=='__main__':raise SystemExit(main())
