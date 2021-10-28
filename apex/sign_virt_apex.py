#!/usr/bin/env python
#
# Copyright (C) 2021 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""sign_virt_apex is a command line tool for sign the Virt APEX file.

Typical usage: sign_virt_apex [-v] [--avbtool path_to_avbtool] path_to_key payload_contents_dir

sign_virt_apex uses external tools which are assumed to be available via PATH.
- avbtool (--avbtool can override the tool)
- lpmake, lpunpack, simg2img, img2simg
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile


def ParseArgs(argv):
    parser = argparse.ArgumentParser(description='Sign the Virt APEX')
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='verbose execution')
    parser.add_argument(
        '--avbtool',
        default='avbtool',
        help='Optional flag that specifies the AVB tool to use. Defaults to `avbtool`.')
    parser.add_argument(
        'key',
        help='path to the private key file.')
    parser.add_argument(
        'input_dir',
        help='the directory having files to be packaged')
    return parser.parse_args(argv)


def RunCommand(args, cmd, env=None, expected_return_values={0}):
    env = env or {}
    env.update(os.environ.copy())

    # TODO(b/193504286): we need a way to find other tool (cmd[0]) in various contexts
    #  e.g. sign_apex.py, sign_target_files_apk.py
    if cmd[0] == 'avbtool':
        cmd[0] = args.avbtool

    if args.verbose:
        print('Running: ' + ' '.join(cmd))
    p = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, universal_newlines=True)
    output, _ = p.communicate()

    if args.verbose or p.returncode not in expected_return_values:
        print(output.rstrip())

    assert p.returncode in expected_return_values, (
        '%d Failed to execute: ' + ' '.join(cmd)) % p.returncode
    return (output, p.returncode)


def ReadBytesSize(value):
    return int(value.removesuffix(' bytes'))


def AvbInfo(args, image_path, descriptor_name=None):
    """Parses avbtool --info image output

    Args:
      args: program arguments.
      image_path: The path to the image.
      descriptor_name: Descriptor name of interest.

    Returns:
      A pair of
        - a dict that contains VBMeta info. None if there's no VBMeta info.
        - a dict that contains target descriptor info. None if name is not specified or not found.
    """
    if not os.path.exists(image_path):
        raise ValueError('Failed to find image: {}'.format(image_path))

    output, ret_code = RunCommand(
        args, ['avbtool', 'info_image', '--image', image_path], expected_return_values={0, 1})
    if ret_code == 1:
        return None, None

    info, descriptor = {}, None

    # Read `avbtool info_image` output as "key:value" lines
    matcher = re.compile(r'^(\s*)([^:]+):\s*(.*)$')

    def IterateLine(output):
        for line in output.split('\n'):
            line_info = matcher.match(line)
            if not line_info:
                continue
            yield line_info.group(1), line_info.group(2), line_info.group(3)

    gen = IterateLine(output)
    # Read VBMeta info
    for _, key, value in gen:
        if key == 'Descriptors':
            break
        info[key] = value

    if descriptor_name:
        for indent, key, _ in gen:
            # Read a target descriptor
            if key == descriptor_name:
                cur_indent = indent
                descriptor = {}
                for indent, key, value in gen:
                    if indent == cur_indent:
                        break
                    descriptor[key] = value
                break

    return info, descriptor


def AddHashFooter(args, key, image_path):
    info, descriptor = AvbInfo(args, image_path, 'Hash descriptor')
    if info:
        image_size = ReadBytesSize(info['Image size'])
        algorithm = info['Algorithm']
        partition_name = descriptor['Partition Name']
        partition_size = str(image_size)

        cmd = ['avbtool', 'add_hash_footer',
               '--key', key,
               '--algorithm', algorithm,
               '--partition_name', partition_name,
               '--partition_size', partition_size,
               '--image', image_path]
        RunCommand(args, cmd)


def AddHashTreeFooter(args, key, image_path):
    info, descriptor = AvbInfo(args, image_path, 'Hashtree descriptor')
    if info:
        image_size = ReadBytesSize(info['Image size'])
        algorithm = info['Algorithm']
        partition_name = descriptor['Partition Name']
        partition_size = str(image_size)

        cmd = ['avbtool', 'add_hashtree_footer',
               '--key', key,
               '--algorithm', algorithm,
               '--partition_name', partition_name,
               '--partition_size', partition_size,
               '--do_not_generate_fec',
               '--image', image_path]
        RunCommand(args, cmd)


def MakeVbmetaImage(args, key, vbmeta_img, images):
    info, _ = AvbInfo(args, vbmeta_img)
    if info:
        algorithm = info['Algorithm']
        rollback_index = info['Rollback Index']
        rollback_index_location = info['Rollback Index Location']

        cmd = ['avbtool', 'make_vbmeta_image',
               '--key', key,
               '--algorithm', algorithm,
               '--rollback_index', rollback_index,
               '--rollback_index_location', rollback_index_location,
               '--output', vbmeta_img]
        for img in images:
            cmd.extend(['--include_descriptors_from_image', img])
        RunCommand(args, cmd)
        # libavb expects to be able to read the maximum vbmeta size, so we must provide a partition
        # which matches this or the read will fail.
        RunCommand(args, ['truncate', '-s', '65536', vbmeta_img])


class TempDirectory(object):

    def __enter__(self):
        self.name = tempfile.mkdtemp()
        return self.name

    def __exit__(self, *unused):
        shutil.rmtree(self.name)


def MakeSuperImage(args, partitions, output):
    with TempDirectory() as work_dir:
        cmd = ['lpmake', '--device-size=auto', '--metadata-slots=2',  # A/B
               '--metadata-size=65536', '--sparse', '--output=' + output]

        for part, img in partitions.items():
            tmp_img = os.path.join(work_dir, part)
            RunCommand(args, ['img2simg', img, tmp_img])

            image_arg = '--image=%s=%s' % (part, img)
            partition_arg = '--partition=%s:readonly:%d:default' % (
                part, os.path.getsize(img))
            cmd.extend([image_arg, partition_arg])

        RunCommand(args, cmd)


def ReplaceBootloaderPubkey(args, key, bootloader, bootloader_pubkey):
    # read old pubkey before replacement
    with open(bootloader_pubkey, 'rb') as f:
        old_pubkey = f.read()

    # replace bootloader pubkey
    RunCommand(args, ['avbtool', 'extract_public_key', '--key', key, '--output', bootloader_pubkey])

    # read new pubkey
    with open(bootloader_pubkey, 'rb') as f:
        new_pubkey = f.read()

    assert len(old_pubkey) == len(new_pubkey)

    # replace pubkey embedded in bootloader
    with open(bootloader, 'r+b') as bl_f:
        pos = bl_f.read().find(old_pubkey)
        assert pos != -1
        bl_f.seek(pos)
        bl_f.write(new_pubkey)


def SignVirtApex(args):
    key = args.key
    input_dir = args.input_dir

    # target files in the Virt APEX
    bootloader_pubkey = os.path.join(input_dir, 'etc', 'microdroid_bootloader.avbpubkey')
    bootloader = os.path.join(input_dir, 'etc', 'microdroid_bootloader')
    boot_img = os.path.join(input_dir, 'etc', 'fs', 'microdroid_boot-5.10.img')
    vendor_boot_img = os.path.join(
        input_dir, 'etc', 'fs', 'microdroid_vendor_boot-5.10.img')
    super_img = os.path.join(input_dir, 'etc', 'fs', 'microdroid_super.img')
    vbmeta_img = os.path.join(input_dir, 'etc', 'fs', 'microdroid_vbmeta.img')

    # Key(pubkey) for bootloader should match with the one used to make VBmeta below
    # while it's okay to use different keys for other image files.
    ReplaceBootloaderPubkey(args, key, bootloader, bootloader_pubkey)

    # re-sign bootloader, boot.img, vendor_boot.img
    AddHashFooter(args, key, bootloader)
    AddHashFooter(args, key, boot_img)
    AddHashFooter(args, key, vendor_boot_img)

    # re-sign super.img
    with TempDirectory() as work_dir:
        # unpack super.img
        tmp_super_img = os.path.join(work_dir, 'super.img')
        RunCommand(args, ['simg2img', super_img, tmp_super_img])
        RunCommand(args, ['lpunpack', tmp_super_img, work_dir])

        system_a_img = os.path.join(work_dir, 'system_a.img')
        vendor_a_img = os.path.join(work_dir, 'vendor_a.img')
        partitions = {"system_a": system_a_img, "vendor_a": vendor_a_img}

        # re-sign partitions in super.img
        for img in partitions.values():
            AddHashTreeFooter(args, key, img)

        # re-pack super.img
        MakeSuperImage(args, partitions, super_img)

        # re-generate vbmeta from re-signed {boot, vendor_boot, system_a, vendor_a}.img
        # Ideally, making VBmeta should be done out of TempDirectory block. But doing it here
        # to avoid unpacking re-signed super.img for system/vendor images which are available
        # in this block.
        MakeVbmetaImage(args, key, vbmeta_img, [
                        boot_img, vendor_boot_img, system_a_img, vendor_a_img])


def main(argv):
    try:
        args = ParseArgs(argv)
        SignVirtApex(args)
    except Exception as e:
        print(e)
        sys.exit(1)


if __name__ == '__main__':
    main(sys.argv[1:])
