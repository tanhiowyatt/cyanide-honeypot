
import os
import sys
import unittest
from pathlib import Path

# Add src to python path
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from cyanide.fs.yaml_fs import load_fs
from cyanide.vfs.nodes import Directory, File

class TestYamlFS(unittest.TestCase):
    def setUp(self):
        self.yaml_path = Path("test_fs.yaml")
        with open(self.yaml_path, "w") as f:
            f.write("""
name: ""
type: directory
perm: drwxr-xr-x
owner: root
group: root
children:
  - name: etc
    type: directory
    perm: drwxr-xr-x
    children:
      - name: passwd
        type: file
        perm: "-rw-r--r--"
        content: "root:x:0:0:root:/root:/bin/bash"
""")

    def tearDown(self):
        if self.yaml_path.exists():
            os.remove(self.yaml_path)

    def test_load_fs(self):
        root, metadata = load_fs(str(self.yaml_path))
        self.assertIsInstance(root, Directory)
        self.assertEqual(root.name, "")
        self.assertEqual(len(root.children), 1)
        
        etc = root.children["etc"]
        self.assertIsInstance(etc, Directory)
        self.assertEqual(etc.name, "etc")
        
        passwd = etc.children["passwd"]
        self.assertIsInstance(passwd, File)
        self.assertEqual(passwd.name, "passwd")
        self.assertEqual(passwd.content, "root:x:0:0:root:/root:/bin/bash")

if __name__ == "__main__":
    unittest.main()
