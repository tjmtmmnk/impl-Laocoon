from administrator import Administrator
from bulletinboard import BulletinBoard

admin = Administrator()
bb = BulletinBoard.get_instance()

admin.setup()
bb.show()