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
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.example.auth.app.main.FileManager;
import com.example.auth.app.main.MyActivity;
import com.example.auth.app.ulctools.Reader;
import com.example.vaarajer1.auth.R;

/**
 * Created by vaarajer1 on 7/17/14.
 */
public class ConsolePopup extends DialogFragment {

    private TextView console;
    private ScrollView scrollView;
    private Button btn_archive;
    private TextView console_hint;
    private View.OnClickListener btn_archive_listener = new View.OnClickListener() {
        public void onClick(View v) {
            FileManager.saveLog(MyActivity.outer);
            console.setText("");
            Reader.history = "";
            console_hint.setVisibility(View.VISIBLE);
        }
    };

    public ConsolePopup() {
        // Empty constructor required for DialogFragment
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.console_popup, container);
        console = (TextView) view.findViewById(R.id.console);
        scrollView = (ScrollView) view.findViewById(R.id.scrollView);
        console.setText(Reader.history);
        btn_archive = (Button) view.findViewById(R.id.btn_console_archive);

        btn_archive.setOnClickListener(btn_archive_listener);

        console_hint = (TextView) view.findViewById(R.id.console_hint);

        if (console.getText().length() >= 1) {
            console_hint.setVisibility(View.GONE);
        }

        this.update();

        return view;
    }

    public void update() {
        console.setText(Reader.history);
        if (console.getText().length() >= 1) {
            console_hint.setVisibility(View.GONE);
        }
        scrollView.post(new Runnable() {
            @Override
            public void run() {
                scrollView.fullScroll(View.FOCUS_DOWN);
            }
        });

    }
}
