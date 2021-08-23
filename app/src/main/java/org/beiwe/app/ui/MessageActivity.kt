package org.beiwe.app.ui

import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import kotlinx.android.synthetic.main.activity_message.*
import org.beiwe.app.R

class MessageActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_message)
        val messageContent = intent.getStringExtra("messageContent")

        if (messageContent != null) {
            messageScreenTextView.text = messageContent
        }
    }
}