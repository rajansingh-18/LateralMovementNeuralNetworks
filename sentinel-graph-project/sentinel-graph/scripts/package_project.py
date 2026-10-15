"""Build the downloadable Windows project from tracked source and compiled frontend."""
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
ROOT=Path(__file__).resolve().parents[1]
target=ROOT/'dist/sentinel-graph-project.zip'
exclude={'.git','.openai','node_modules','.venv','__pycache__','.pytest_cache','.wrangler','.sites','upload'}
with ZipFile(target,'w',ZIP_DEFLATED,compresslevel=6) as z:
    for p in sorted(ROOT.rglob('*')):
        rel=p.relative_to(ROOT)
        if not p.is_file() or p==target or set(rel.parts)&exclude:continue
        if p.suffix in {'.db','.pyc','.gz'} or '.db-' in p.name:continue
        if rel.parts[0]=='data' and p.name.startswith('dataset'):continue
        if rel.parts[0]=='logs':continue
        z.write(p,Path('sentinel-graph')/rel)
print(f'Windows project packaged: {target.name} ({target.stat().st_size:,} bytes)')
