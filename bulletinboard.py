
class BulletinBoard:
    _unique_instance = None

    def __new__(cls):
        raise NotImplementedError('Cannot initialize via Constructor')

    @classmethod
    def __internal_new__(cls):
        return super().__new__(cls)

    @classmethod
    def get_instance(cls):
        if not cls._unique_instance:
            cls.board = []
            cls._unique_instance = cls.__internal_new__()

        return cls._unique_instance

    def append(self, value):
        self.board.append(value)

    def show(self):
        for content in self.board:
            print(content)