cd c:\Users\abrisske\.source\python-egnyte
@'
import sys
from egnyte import EgnyteClient

path = sys.argv[1] if len(sys.argv) > 1 else "/Shared"
for f in sorted(EgnyteClient().folder(path).list().folders, key=lambda f: f.path.lower()):
    print(f.path)
'@ | python - "/Shared/Teams/IT/Infrastructure/Azure App Test"
