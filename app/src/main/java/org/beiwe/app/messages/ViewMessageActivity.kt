package org.beiwe.app.messages

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import kotlinx.android.synthetic.main.activity_view_message.*
import org.beiwe.app.R

class ViewMessageActivity : AppCompatActivity() {
    var messageId: String? = null


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_view_message)
        messageId = intent.getStringExtra("surveyOrMessageId")
        val message = getStoredMessage(messageId)
        if (message != null) {
            messageContentTextView.setText(message.content)
        }
    }


    fun deleteMessage(view: View) {
        deleteMessage(messageId, applicationContext)
        this.finish()
    }
}