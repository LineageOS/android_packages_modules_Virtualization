/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.virt.test;

import static org.junit.Assert.*;

import com.android.tradefed.testtype.DeviceTestCase;
import com.android.tradefed.testtype.IAbi;
import com.android.tradefed.testtype.IAbiReceiver;

import org.junit.Before;

import java.util.ArrayList;

public abstract class VirtTestCase extends DeviceTestCase implements IAbiReceiver {

    private static final String DEVICE_DIR = "/data/local/tmp/virt-test";

    private static final int CID_RESERVED = 2;

    private IAbi mAbi;

    @Before
    public void setUp() throws Exception {
        getDevice().waitForDeviceAvailable();
    }

    private String getAbiName() {
        String name = mAbi.getName();
        if ("arm64-v8a".equals(name)) {
            name = "arm64";
        }
        return name;
    }

    protected String getDevicePathForTestBinary(String targetName) throws Exception {
        String path = String.format("%s/%s/%s", DEVICE_DIR, getAbiName(), targetName);
        if (!getDevice().doesFileExist(path)) {
            throw new IllegalArgumentException(String.format(
                    "Binary for target %s not found on device at \"%s\"", targetName, path));
        }
        return path;
    }

    protected static String createCommand(String prog, Object... args) {
        ArrayList<String> strings = new ArrayList<>();
        strings.add(prog);
        for (Object arg : args) {
            strings.add(arg.toString());
        }
        for (String str : strings) {
            if (str.indexOf(' ') != -1) {
                throw new IllegalArgumentException("TODO: implement quotes around arguments");
            } else if (str.indexOf('\'') != -1) {
                throw new IllegalArgumentException("TODO: implement escaping arguments");
            }
        }
        return String.join(" ", strings);
    }

    protected String getVmCommand(String guestCmd, Integer cid) throws Exception {
        ArrayList<String> cmd = new ArrayList<>();

        cmd.add("crosvm");
        cmd.add("run");

        cmd.add("--disable-sandbox");

        if (cid != null) {
            if (cid > CID_RESERVED) {
                cmd.add("--cid");
                cmd.add(cid.toString());
            } else {
                throw new IllegalArgumentException("Invalid CID " + cid);
            }
        }

        cmd.add("--initrd");
        cmd.add(getDevicePathForTestBinary("initramfs"));

        cmd.add("--params");
        cmd.add(String.format("'%s'", guestCmd));

        cmd.add(getDevicePathForTestBinary("kernel"));

        return String.join(" ", cmd);
    }

    @Override
    public void setAbi(IAbi abi) {
        mAbi = abi;
    }
}
