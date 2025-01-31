import os
import sys
import platform
import time
import math
import signal
import threading
import xml.etree.ElementTree as ET
from urllib3 import PoolManager
from binascii import crc32

def download_zwift_version(local_path, version):
    system = platform.system()
    if system == 'Windows':
        file = f'Zwift_ver_cur.{version}.xml'
    elif system == 'Darwin':
        file = f'ZwiftMac_ver_cur.{version}.xml'
    else:
        print("Unsupported platform: %s" % system)
        return

    base_url = 'http://cdn.zwift.com/gameassets/Zwift_Updates_Root/'

    # Update Zwift_ver_cur_filename.txt with the current version file
    with open(os.path.join(local_path, 'Zwift_ver_cur_filename.txt'), 'w') as f:
        f.write(file)

    open(os.path.join(local_path, file), 'wb').write(PoolManager().request('GET', base_url + file).data)

    def sigint_handler(num, frame):
        os._exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    def download(files, folder):
        global downloaded
        manager = PoolManager()
        for file in files:
            path = file.find('path').text
            length = int(file.find('length').text)
            checksum = int(file.find('checksum').text) % (1 << 32)
            file_name = os.path.join(local_path, path.replace('\\', os.sep))
            dir_name = os.path.dirname(file_name)
            if not os.path.isdir(dir_name):
                os.makedirs(dir_name)
            while not os.path.isfile(file_name) or os.path.getsize(file_name) != length or (crc32(open(file_name, 'rb').read()) != checksum and checksum != 4294967295):
                open(file_name, 'wb').write(manager.request('GET', '%s%s/%s' % (base_url, folder, path.replace('\\', '/'))).data)
            downloaded += 1

    tree = ET.parse(os.path.join(local_path, file))
    root = tree.getroot()
    manifest = root.get('manifest')
    manifest_checksum = int(root.get('manifest_checksum')) % (1 << 32)
    manifest_file = os.path.join(local_path, manifest)
    while not os.path.isfile(manifest_file) or crc32(open(manifest_file, 'rb').read()) != manifest_checksum:
        open(manifest_file, 'wb').write(PoolManager().request('GET', base_url + manifest).data)
    tree = ET.parse(manifest_file)
    root = tree.getroot()
    folder = root.get('folder')
    all_files = list(root.iter('file'))
    total = len(all_files)
    global downloaded
    downloaded = 0
    threads = 5
    c = math.ceil(total / threads)
    for i in range(0, threads):
        files = all_files[i * c:i * c + c]
        thread = threading.Thread(target=download, args=(files, folder))
        thread.start()
    print("Downloading files from %s" % manifest)
    while True:
        time.sleep(1)
        completed = 50 * downloaded // total
        print('\r[%s] %s%% (%s of %s)' % ('#' * completed + '.' * (50 - completed), round(100 * downloaded / total, 1), downloaded, total), end='', flush=True)
        if downloaded == total:
            break
    print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Use %s <version>" % sys.argv[0])
        exit()
    
    version = sys.argv[1]
    if platform.system() == 'Windows':
        default_path = 'C:\\Program Files (x86)\\Zwift'
    elif platform.system() == 'Darwin':
        default_path = '~/Library/Application Support/Zwift'
    else:
        print("Unsupported platform")
        exit()
    
    download_zwift_version(default_path, version)