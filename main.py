from administrator import Administrator
from bulletinboard import BulletinBoard
from candidate import Candidate

admin = Administrator()
cand1 = Candidate("cand1")
cand2 = Candidate("cand2")

bb = BulletinBoard.get_instance()

admin.setup([cand1.public_key, cand2.public_key])
admin.credential_dispatch()
bb.show()
