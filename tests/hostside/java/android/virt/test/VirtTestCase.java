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

import org.junit.Before;

import java.util.ArrayList;

public abstract class VirtTestCase extends DeviceTestCase {

    private static final String DEVICE_DIR = "/data/local/tmp/virt-test";

    @Before
    public void setUp() throws Exception {
        getDevice().waitForDeviceAvailable();
    }

    protected String getDevicePathForTestBinary(String targetName) throws Exception {
        String path = String.format("%s/%s", DEVICE_DIR, targetName);
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

}
