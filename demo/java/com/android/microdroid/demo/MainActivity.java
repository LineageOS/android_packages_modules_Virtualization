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

package com.android.microdroid.demo;

import android.app.Application;
import android.os.Bundle;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelProvider;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * This app is to demonstrate the use of APIs in the android.system.virtualmachine library.
 * Currently, this app starts a virtual machine running Microdroid and shows the console output from
 * the virtual machine to the UI.
 */
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Whenthe console model is updated, append the new line to the text view.
        TextView view = (TextView) findViewById(R.id.textview);
        VirtualMachineModel model = new ViewModelProvider(this).get(VirtualMachineModel.class);
        model.getConsoleOutput()
                .observeForever(
                        new Observer<String>() {
                            @Override
                            public void onChanged(String line) {
                                view.append(line + "\n");
                            }
                        });
    }

    /** Models a virtual machine and console output from it. */
    public static class VirtualMachineModel extends AndroidViewModel {
        private final VirtualMachine mVirtualMachine;
        private final MutableLiveData<String> mConsoleOutput = new MutableLiveData<>();

        public VirtualMachineModel(Application app) {
            super(app);

            // Create a VM and run it.
            // TODO(jiyong): remove the call to idsigPath
            try {
                VirtualMachineConfig config =
                        new VirtualMachineConfig.Builder(getApplication(), "assets/vm_config.json")
                                .idsigPath("/data/local/tmp/virt/MicrodroidDemoApp.apk.idsig")
                                .build();
                VirtualMachineManager vmm = VirtualMachineManager.getInstance(getApplication());
                mVirtualMachine = vmm.create("demo_vm", config);
                mVirtualMachine.run();
            } catch (VirtualMachineException e) {
                throw new RuntimeException(e);
            }

            // Read console output from the VM in the background
            ExecutorService executorService = Executors.newFixedThreadPool(1);
            executorService.execute(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                BufferedReader reader =
                                        new BufferedReader(
                                                new InputStreamReader(
                                                        mVirtualMachine.getConsoleOutputStream()));
                                while (true) {
                                    String line = reader.readLine();
                                    mConsoleOutput.postValue(line);
                                }
                            } catch (IOException | VirtualMachineException e) {
                                // Consume
                            }
                        }
                    });
        }

        public LiveData<String> getConsoleOutput() {
            return mConsoleOutput;
        }
    }
}
