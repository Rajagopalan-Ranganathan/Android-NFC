package com.example.auth.app.fragments;
/**
 * Developed for Aalto-university course T-110.5241 Network Security.
 * Copyright (C) 2014 Jere Vaara
 */
import android.app.DialogFragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.TextView;

import com.example.auth.app.ulctools.Reader;
import com.example.vaarajer1.auth.R;

public class ErasePopup extends DialogFragment {

    private Button btn_erase;
    private Button btn_erase_cancel;
    private CheckBox checkBox_erase_auth;
    private TextView current_key;

    private boolean erase_auth = false;

    private View.OnClickListener btn_erase_listener = new View.OnClickListener() {
        public void onClick(View v) {
            if (Reader.connect()) {
                Reader.erase(erase_auth);
                Reader.setAuth0(48, false);
                Reader.setAuth1(false, false);
                Reader.disconnect();
                ToolsFragment.update();
            }
            dismiss();
        }
    };
    private View.OnClickListener btn_erase_cancel_listener = new View.OnClickListener() {
        public void onClick(View v) {
            dismiss();
        }
    };

    public ErasePopup() {
        // Empty constructor required for DialogFragment
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.erase_popup, container);

        btn_erase = (Button) view.findViewById(R.id.btn_erase);
        btn_erase_cancel = (Button) view.findViewById(R.id.btn_erase_cancel);

        current_key = (TextView) view.findViewById(R.id.current_auth_key);

        checkBox_erase_auth = (CheckBox) view.findViewById(R.id.check_box_erase_auth);
        checkBox_erase_auth.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                if (((CheckBox) v).isChecked()) {
                    erase_auth = true;
                    current_key.setText("Key in use: " + Reader.authKey);
                    current_key.setAlpha(255);
                } else {
                    erase_auth = false;
                    current_key.setAlpha(0);
                }

            }
        });

        btn_erase.setOnClickListener(btn_erase_listener);
        btn_erase_cancel.setOnClickListener(btn_erase_cancel_listener);

        return view;
    }

}
