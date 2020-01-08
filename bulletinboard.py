from typing import List


class BulletinBoard:
    _unique_instance = None

    def __new__(self):
        raise NotImplementedError('Cannot initialize via Constructor')

    @classmethod
    def __internal_new__(self):
        return super().__new__(self)

    @classmethod
    def get_instance(self):
        if not self._unique_instance:
            self.board = []
            self._unique_instance = self.__internal_new__()

        return self._unique_instance

    def append(self, value):
        self.board.append(value)

    def find_by_key(self, key: str):
        for content in self.board:
            value = content.get(key)
            if value is not None:
                return value

    def show(self):
        for content in self.board:
            print(content)
