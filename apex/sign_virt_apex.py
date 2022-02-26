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

Typical usage:
  sign_virt_apex [-v] [--avbtool path_to_avbtool] [--signing_args args] payload_key payload_dir

sign_virt_apex uses external tools which are assumed to be available via PATH.
- avbtool (--avbtool can override the tool)
- lpmake, lpunpack, simg2img, img2simg
"""
import argparse
import glob
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


def ParseArgs(argv):
    parser = argparse.ArgumentParser(description='Sign the Virt APEX')
    parser.add_argument('--verify', action='store_true',
                        help='Verify the Virt APEX')
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='verbose execution')
    parser.add_argument(
        '--avbtool',
        default='avbtool',
        help='Optional flag that specifies the AVB tool to use. Defaults to `avbtool`.')
    parser.add_argument(
        '--signing_args',
        help='the extra signing arguments passed to avbtool.'
    )
    parser.add_argument(
        '--key_override',
        metavar="filename=key",
        action='append',
        help='Overrides a signing key for a file e.g. microdroid_bootloader=mykey (for testing)')
    parser.add_argument(
        'key',
        help='path to the private key file.')
    parser.add_argument(
        'input_dir',
        help='the directory having files to be packaged')
    args = parser.parse_args(argv)
    # preprocess --key_override into a map
    args.key_overrides = dict()
    if args.key_override:
        for pair in args.key_override:
            name, key = pair.split('=')
            args.key_overrides[name] = key
    return args


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


def ExtractAvbPubkey(args, key, output):
    RunCommand(args, ['avbtool', 'extract_public_key',
               '--key', key, '--output', output])


def AvbInfo(args, image_path):
    """Parses avbtool --info image output

    Args:
      args: program arguments.
      image_path: The path to the image.
      descriptor_name: Descriptor name of interest.

    Returns:
      A pair of
        - a dict that contains VBMeta info. None if there's no VBMeta info.
        - a list of descriptors.
    """
    if not os.path.exists(image_path):
        raise ValueError('Failed to find image: {}'.format(image_path))

    output, ret_code = RunCommand(
        args, ['avbtool', 'info_image', '--image', image_path], expected_return_values={0, 1})
    if ret_code == 1:
        return None, None

    info, descriptors = {}, []

    # Read `avbtool info_image` output as "key:value" lines
    matcher = re.compile(r'^(\s*)([^:]+):\s*(.*)$')

    def IterateLine(output):
        for line in output.split('\n'):
            line_info = matcher.match(line)
            if not line_info:
                continue
            yield line_info.group(1), line_info.group(2), line_info.group(3)

    gen = IterateLine(output)

    def ReadDescriptors(cur_indent, cur_name, cur_value):
        descriptor = cur_value if cur_name == 'Prop' else {}
        descriptors.append((cur_name, descriptor))
        for indent, key, value in gen:
            if indent <= cur_indent:
                # read descriptors recursively to pass the read key as descriptor name
                ReadDescriptors(indent, key, value)
                break
            descriptor[key] = value

    # Read VBMeta info
    for _, key, value in gen:
        if key == 'Descriptors':
            ReadDescriptors(*next(gen))
            break
        info[key] = value

    return info, descriptors


# Look up a list of (key, value) with a key. Returns the value of the first matching pair.
def LookUp(pairs, key):
    for k, v in pairs:
        if key == k:
            return v
    return None


def AddHashFooter(args, key, image_path):
    if os.path.basename(image_path) in args.key_overrides:
        key = args.key_overrides[os.path.basename(image_path)]
    info, descriptors = AvbInfo(args, image_path)
    if info:
        descriptor = LookUp(descriptors, 'Hash descriptor')
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
        if args.signing_args:
            cmd.extend(shlex.split(args.signing_args))
        RunCommand(args, cmd)


def AddHashTreeFooter(args, key, image_path):
    if os.path.basename(image_path) in args.key_overrides:
        key = args.key_overrides[os.path.basename(image_path)]
    info, descriptors = AvbInfo(args, image_path)
    if info:
        descriptor = LookUp(descriptors, 'Hashtree descriptor')
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
        if args.signing_args:
            cmd.extend(shlex.split(args.signing_args))
        RunCommand(args, cmd)


def MakeVbmetaImage(args, key, vbmeta_img, images=None, chained_partitions=None):
    if os.path.basename(vbmeta_img) in args.key_overrides:
        key = args.key_overrides[os.path.basename(vbmeta_img)]
    info, descriptors = AvbInfo(args, vbmeta_img)
    if info is None:
        return

    with TempDirectory() as work_dir:
        algorithm = info['Algorithm']
        rollback_index = info['Rollback Index']
        rollback_index_location = info['Rollback Index Location']

        cmd = ['avbtool', 'make_vbmeta_image',
               '--key', key,
               '--algorithm', algorithm,
               '--rollback_index', rollback_index,
               '--rollback_index_location', rollback_index_location,
               '--output', vbmeta_img]
        if images:
            for img in images:
                cmd.extend(['--include_descriptors_from_image', img])

        # replace pubkeys of chained_partitions as well
        for name, descriptor in descriptors:
            if name == 'Chain Partition descriptor':
                part_name = descriptor['Partition Name']
                ril = descriptor['Rollback Index Location']
                part_key = chained_partitions[part_name]
                avbpubkey = os.path.join(work_dir, part_name + '.avbpubkey')
                ExtractAvbPubkey(args, part_key, avbpubkey)
                cmd.extend(['--chain_partition', '%s:%s:%s' %
                           (part_name, ril, avbpubkey)])

        if args.signing_args:
            cmd.extend(shlex.split(args.signing_args))

        RunCommand(args, cmd)
        # libavb expects to be able to read the maximum vbmeta size, so we must provide a partition
        # which matches this or the read will fail.
        with open(vbmeta_img, 'a') as f:
            f.truncate(65536)


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
    if os.path.basename(bootloader) in args.key_overrides:
        key = args.key_overrides[os.path.basename(bootloader)]
    # read old pubkey before replacement
    with open(bootloader_pubkey, 'rb') as f:
        old_pubkey = f.read()

    # replace bootloader pubkey (overwrite the old one with the new one)
    ExtractAvbPubkey(args, key, bootloader_pubkey)

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
    bootloader_pubkey = os.path.join(
        input_dir, 'etc', 'microdroid_bootloader.avbpubkey')
    bootloader = os.path.join(input_dir, 'etc', 'microdroid_bootloader')
    boot_img = os.path.join(input_dir, 'etc', 'fs', 'microdroid_boot-5.10.img')
    vendor_boot_img = os.path.join(
        input_dir, 'etc', 'fs', 'microdroid_vendor_boot-5.10.img')
    init_boot_img = os.path.join(
        input_dir, 'etc', 'fs', 'microdroid_init_boot.img')
    super_img = os.path.join(input_dir, 'etc', 'fs', 'microdroid_super.img')
    vbmeta_img = os.path.join(input_dir, 'etc', 'fs', 'microdroid_vbmeta.img')
    vbmeta_bootconfig_img = os.path.join(
        input_dir, 'etc', 'fs', 'microdroid_vbmeta_bootconfig.img')
    bootconfig_normal = os.path.join(
        input_dir, 'etc', 'microdroid_bootconfig.normal')
    bootconfig_app_debuggable = os.path.join(
        input_dir, 'etc', 'microdroid_bootconfig.app_debuggable')
    bootconfig_full_debuggable = os.path.join(
        input_dir, 'etc', 'microdroid_bootconfig.full_debuggable')
    uboot_env_img = os.path.join(
        input_dir, 'etc', 'uboot_env.img')

    # Key(pubkey) for bootloader should match with the one used to make VBmeta below
    # while it's okay to use different keys for other image files.
    ReplaceBootloaderPubkey(args, key, bootloader, bootloader_pubkey)

    # re-sign bootloader, boot.img, vendor_boot.img, and init_boot.img
    AddHashFooter(args, key, bootloader)
    AddHashFooter(args, key, boot_img)
    AddHashFooter(args, key, vendor_boot_img)
    AddHashFooter(args, key, init_boot_img)

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

        # re-generate vbmeta from re-signed {boot, vendor_boot, init_boot, system_a, vendor_a}.img
        # Ideally, making VBmeta should be done out of TempDirectory block. But doing it here
        # to avoid unpacking re-signed super.img for system/vendor images which are available
        # in this block.
        MakeVbmetaImage(args, key, vbmeta_img, images=[
                        boot_img, vendor_boot_img, init_boot_img, system_a_img, vendor_a_img])

    # Re-sign bootconfigs and the uboot_env with the same key
    bootconfig_sign_key = key
    AddHashFooter(args, bootconfig_sign_key, bootconfig_normal)
    AddHashFooter(args, bootconfig_sign_key, bootconfig_app_debuggable)
    AddHashFooter(args, bootconfig_sign_key, bootconfig_full_debuggable)
    AddHashFooter(args, bootconfig_sign_key, uboot_env_img)

    # Re-sign vbmeta_bootconfig with chained_partitions to "bootconfig" and
    # "uboot_env". Note that, for now, `key` and `bootconfig_sign_key` are the
    # same, but technically they can be different. Vbmeta records pubkeys which
    # signed chained partitions.
    MakeVbmetaImage(args, key, vbmeta_bootconfig_img, chained_partitions={
                    'bootconfig': bootconfig_sign_key,
                    'uboot_env': bootconfig_sign_key,
    })


def VerifyVirtApex(args):
    # Generator to emit avbtool-signed items along with its pubkey digest.
    # This supports lpmake-packed images as well.
    def Recur(target_dir):
        for file in glob.glob(os.path.join(target_dir, 'etc', '**', '*'), recursive=True):
            cur_item = os.path.relpath(file, target_dir)

            if not os.path.isfile(file):
                continue

            # avbpubkey
            if cur_item == 'etc/microdroid_bootloader.avbpubkey':
                with open(file, 'rb') as f:
                    yield (cur_item, hashlib.sha1(f.read()).hexdigest())
                continue

            # avbtool signed
            info, _ = AvbInfo(args, file)
            if info:
                yield (cur_item, info['Public key (sha1)'])
                continue

            # logical partition
            with TempDirectory() as tmp_dir:
                unsparsed = os.path.join(tmp_dir, os.path.basename(file))
                _, rc = RunCommand(
                    # exit with 255 if it's not sparsed
                    args, ['simg2img', file, unsparsed], expected_return_values={0, 255})
                if rc == 0:
                    with TempDirectory() as unpack_dir:
                        # exit with 64 if it's not a logical partition.
                        _, rc = RunCommand(
                            args, ['lpunpack', unsparsed, unpack_dir], expected_return_values={0, 64})
                        if rc == 0:
                            nested_items = list(Recur(unpack_dir))
                            if len(nested_items) > 0:
                                for (item, key) in nested_items:
                                    yield ('%s!/%s' % (cur_item, item), key)
                                continue
    # Read pubkey digest
    with TempDirectory() as tmp_dir:
        pubkey_file = os.path.join(tmp_dir, 'avbpubkey')
        ExtractAvbPubkey(args, args.key, pubkey_file)
        with open(pubkey_file, 'rb') as f:
            pubkey_digest = hashlib.sha1(f.read()).hexdigest()

    # Check every avbtool-signed item against the input key
    for (item, pubkey) in Recur(args.input_dir):
        assert pubkey == pubkey_digest, '%s: key mismatch: %s != %s' % (
            item, pubkey, pubkey_digest)


def main(argv):
    try:
        args = ParseArgs(argv)
        if args.verify:
            VerifyVirtApex(args)
        else:
            SignVirtApex(args)
    except Exception as e:
        print(e)
        sys.exit(1)


if __name__ == '__main__':
    main(sys.argv[1:])
