package org.beiwe.app.messages

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import kotlinx.android.synthetic.main.activity_view_message.*
import org.beiwe.app.R

class ViewMessageActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_view_message)
        val messageId = intent.getStringExtra("surveyOrMessageId")
        if (messageId != null) {
            val message = getStoredMessage(messageId)
            if (message != null) {
                messageScreenTextView.text = message.content
            }
        }
    }
}