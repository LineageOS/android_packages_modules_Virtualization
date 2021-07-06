/*
 * Copyright (C) 2021 The Android Open Source Project
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
package com.android.microdroid.test;

import android.app.Activity;
import android.os.Bundle;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;

public class TestActivity extends Activity {

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        VirtualMachine vm1 = createAndRunVirtualMachine("vm1");
        VirtualMachine vm2 = createAndRunVirtualMachine("vm2");
    }

    private VirtualMachine createAndRunVirtualMachine(String name) {
        VirtualMachine vm;
        try {
            VirtualMachineConfig config =
                    new VirtualMachineConfig.Builder(this, "assets/vm_config.json")
                            .idsigPath("/data/local/tmp/virt/MicrodroidTestApp.apk.idsig")
                            .build();

            VirtualMachineManager vmm = VirtualMachineManager.getInstance(this);
            vm = vmm.create(name, config);
            vm.run();
        } catch (VirtualMachineException e) {
            throw new RuntimeException(e);
        }
        return vm;
    }
}
