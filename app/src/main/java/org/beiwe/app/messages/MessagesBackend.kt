package org.beiwe.app.messages

import android.util.Log
import com.google.gson.Gson
import org.beiwe.app.storage.PersistentData


fun addNewMessage(newMessage: String) {
    val gson = Gson()
    val storedMessagesData = PersistentData.getStoredMessages()
    val storedMessagesArray = gson.fromJson(storedMessagesData, Array<StoredMessage>::class.java)
    var storedMessages: MutableList<StoredMessage> = storedMessagesArray?.toMutableList()
        ?: mutableListOf()
    storedMessages.add(StoredMessage(newMessage, "about now"))
    val newJson = gson.toJson(storedMessages)
    Log.i("JoshLog", "newMessagesJson:")
    Log.i("JoshLog", newJson.toString())
    PersistentData.setStoredMessages(newJson.toString())
}


class StoredMessage(
    var content: String = "",
    var receivedOn: String = ""  // TODO: store actual datetimes in a useful format
)
