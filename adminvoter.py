import uuid

# Voter managed by admin


class AdminVoter:
    def __init__(self, short_public_key, short_private_key):
        self.id = str(uuid.uuid4())
        self.short_public_key = short_public_key
        self.short_private_key = short_private_key
