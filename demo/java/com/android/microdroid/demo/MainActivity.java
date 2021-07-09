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
import android.os.ParcelFileDescriptor;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelProvider;

import java.io.BufferedReader;
import java.io.FileInputStream;
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
        TextView consoleView = (TextView) findViewById(R.id.consoleOutput);
        TextView payloadView = (TextView) findViewById(R.id.payloadOutput);
        Button runStopButton = (Button) findViewById(R.id.runStopButton);
        ScrollView scrollView = (ScrollView) findViewById(R.id.scrollConsoleOutput);

        // When the console output or payload output is updated, append the new line to the
        // corresponding text view.
        VirtualMachineModel model = new ViewModelProvider(this).get(VirtualMachineModel.class);
        model.getConsoleOutput()
                .observeForever(
                        new Observer<String>() {
                            @Override
                            public void onChanged(String line) {
                                consoleView.append(line + "\n");
                                scrollView.fullScroll(View.FOCUS_DOWN);
                            }
                        });
        model.getPayloadOutput()
                .observeForever(
                        new Observer<String>() {
                            @Override
                            public void onChanged(String line) {
                                payloadView.append(line + "\n");
                            }
                        });

        // When the VM status is updated, change the label of the button
        model.getStatus()
                .observeForever(
                        new Observer<VirtualMachine.Status>() {
                            @Override
                            public void onChanged(VirtualMachine.Status status) {
                                if (status == VirtualMachine.Status.RUNNING) {
                                    runStopButton.setText("Stop");
                                    consoleView.setText("");
                                    payloadView.setText("");
                                } else {
                                    runStopButton.setText("Run");
                                }
                            }
                        });

        // When the button is clicked, run or stop the VM
        runStopButton.setOnClickListener(
                new View.OnClickListener() {
                    public void onClick(View v) {
                        if (model.getStatus().getValue() == VirtualMachine.Status.RUNNING) {
                            model.stop();
                        } else {
                            CheckBox debugModeCheckBox = (CheckBox) findViewById(R.id.debugMode);
                            final boolean debug = debugModeCheckBox.isChecked();
                            model.run(debug);
                        }
                    }
                });
    }

    /** Models a virtual machine and console output from it. */
    public static class VirtualMachineModel extends AndroidViewModel {
        private VirtualMachine mVirtualMachine;
        private final MutableLiveData<String> mConsoleOutput = new MutableLiveData<>();
        private final MutableLiveData<String> mPayloadOutput = new MutableLiveData<>();
        private final MutableLiveData<VirtualMachine.Status> mStatus = new MutableLiveData<>();

        public VirtualMachineModel(Application app) {
            super(app);
            mStatus.setValue(VirtualMachine.Status.DELETED);
        }

        /** Runs a VM */
        public void run(boolean debug) {
            // Create a VM and run it.
            // TODO(jiyong): remove the call to idsigPath
            try {
                VirtualMachineConfig.Builder builder =
                        new VirtualMachineConfig.Builder(getApplication(), "assets/vm_config.json")
                                .idsigPath("/data/local/tmp/virt/MicrodroidDemoApp.apk.idsig")
                                .debugMode(debug);
                VirtualMachineConfig config = builder.build();
                VirtualMachineManager vmm = VirtualMachineManager.getInstance(getApplication());
                mVirtualMachine = vmm.getOrCreate("demo_vm", config);
                mVirtualMachine.run();
                mVirtualMachine.setCallback(
                        new VirtualMachineCallback() {
                            @Override
                            public void onPayloadStarted(
                                    VirtualMachine vm, ParcelFileDescriptor out) {
                                try {
                                    BufferedReader reader =
                                            new BufferedReader(
                                                    new InputStreamReader(
                                                            new FileInputStream(
                                                                    out.getFileDescriptor())));
                                    String line;
                                    while ((line = reader.readLine()) != null) {
                                        mPayloadOutput.postValue(line);
                                    }
                                } catch (IOException e) {
                                    // Consume
                                }
                            }

                            @Override
                            public void onDied(VirtualMachine vm) {
                                mStatus.postValue(VirtualMachine.Status.STOPPED);
                            }
                        });
                mStatus.postValue(mVirtualMachine.getStatus());
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

        /** Stops the running VM */
        public void stop() {
            try {
                mVirtualMachine.stop();
            } catch (VirtualMachineException e) {
                // Consume
            }
            mVirtualMachine = null;
            mStatus.postValue(VirtualMachine.Status.STOPPED);
        }

        /** Returns the console output from the VM */
        public LiveData<String> getConsoleOutput() {
            return mConsoleOutput;
        }

        /** Returns the payload output from the VM */
        public LiveData<String> getPayloadOutput() {
            return mPayloadOutput;
        }

        /** Returns the status of the VM */
        public LiveData<VirtualMachine.Status> getStatus() {
            return mStatus;
        }
    }
}
