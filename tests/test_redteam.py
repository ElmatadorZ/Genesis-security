import contextlib
import io
import unittest

from genesis_security import redteam


class RedTeamTests(unittest.TestCase):
    def test_no_security_failures(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            failures = redteam.main()
        self.assertEqual(failures, 0, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
