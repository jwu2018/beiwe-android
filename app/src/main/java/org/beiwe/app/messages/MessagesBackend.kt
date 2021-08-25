package org.beiwe.app.messages

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import org.beiwe.app.storage.PersistentData
import org.beiwe.app.ui.showMessageNotification
import java.util.*


val GSON = Gson()


private fun getStoredMessages(): MutableMap<String, StoredMessage> {
    val storedMessagesData = PersistentData.getStoredMessages()
    val type = object:TypeToken<Map<String, StoredMessage>>(){}.type
    val storedMessagesMap = GSON.fromJson<Map<String, StoredMessage>>(storedMessagesData, type)
    return storedMessagesMap?.toMutableMap() ?: mutableMapOf()
}


fun getStoredMessage(messageId: String): StoredMessage? {
    val storedMessages = getStoredMessages()
    return storedMessages[messageId]
}


fun showAllMessages(appContext: Context) {
    val storedMessages = getStoredMessages()
    for ((messageId, _) in storedMessages) {
        showMessageNotification(appContext, messageId)
    }
}


fun handleNewMessage(messageContent: String, appContext: Context) {
    // Add the message to the dict of messages stored in JSON in PersistentData
    val storedMessages = getStoredMessages()
    val newMessageId = UUID.randomUUID().toString()
    storedMessages[newMessageId] = StoredMessage(messageContent, "about now")
    val newJson = GSON.toJson(storedMessages)
    Log.i("JoshLog", "newMessagesJson:")
    Log.i("JoshLog", newJson.toString())
    PersistentData.setStoredMessages(newJson.toString())
    // Show the message
    showMessageNotification(appContext, newMessageId)
}


class StoredMessage(
    var content: String = "",
    var receivedOn: String = ""  // TODO: store actual datetimes in a useful format
)
