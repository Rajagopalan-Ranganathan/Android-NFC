package com.example.auth.ticket;

import android.util.Log;

import com.example.auth.app.fragments.TicketFragment;
import com.example.auth.app.ulctools.Commands;
import com.example.auth.app.ulctools.Dump;
import com.example.auth.app.ulctools.Reader;
import com.example.auth.app.ulctools.Utilities;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Date;

/*
* Name: Rajagopalan Ranganathan
* Student# : 601153
* NEtowrk Security Assignment #
*
* */

/**
 * TODO: Complete the implementation of this class. Most of the code are
 * already implemented. You will need to change the keys, design and implement
 * functions to issue the ticket and use it.
 *
 * Method bodies compatible with desktop Java version, but the methods throw different exceptions so only the body can be copied straight!
 *
 */
public class Ticket {

    private static byte[] authenticationKey = "BREAKMEIFYOUCAN!".getBytes();// 16 byte long key
    //The new auth key that is used after a fresh format
    private static byte[] newAuthKey = "1234abcd9876efgh".getBytes();//16 byte long New key
    public static byte[] data = new byte[192];
    private static TicketMac macAlgorithm;
    private static Utilities utils;
    private static Commands ul;
    private static int secsMonth = 2628000;

    private Boolean isValid = false;
    private int remainingUses = 0;

    private int expiryTime = 0;
    public static Boolean isAuthenticated = false;

    private int quick = 0;

    public static String infoToShow; // Use this to show messages in Log and in Tap mode


    // Define a page-4 application tag to use for the ticket application.
    // It will be written to card memory page 4 and used to identify the
    // ticket application.
    public byte[] applicationTag = "TCKT".getBytes();
    private static final int usedMacLength = 2; // Mac length in 4-byte pages.

    public Ticket() throws GeneralSecurityException {
        macAlgorithm = new TicketMac();

        //TODO: Change hmac key according to your need
        byte[] hmacKey = new byte[16];
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    // Do not copy this method to Java version
    public static void dump() {

        if (isAuthenticated == false) {
            utils.authenticate(newAuthKey);
            isAuthenticated = true;

        } else {
            Reader.readMemory(data, false, false);
            TicketFragment.ticket_dump.setText(Dump.hexView(data, 0));
        }
    }

    // Format the card to be used as a ticket.
    public boolean format() {
        boolean status;
       byte[] remainingUsesByte = new byte[4];
        //The card has been formated and issued with the new auth key if we have a valid data in Page 4
        //So use the new auth key
        if(utils.readPages(4, 1, remainingUsesByte, 0) == true)
            utils.authenticate(newAuthKey);
        else //Cannot read page [4] brand new card, use the manufacturer keys to format the carc
            utils.authenticate(authenticationKey);

        // Zero the card memory. Fails is any of the pages is locked.
        status = utils.eraseMemory();
        if (!status)
            return false;

        // Write the application tag to memory page 4.
        status = ul.writeBinary(4, applicationTag, 0);

        if (!status)
            return false;
        // In a real application, we probably would lock some pages here,
        // but remember that locking pages is irreversible.

        // Check the format.
        if (!checkFormat()) {
            return false;
        }

        // Change the authentication key to the user specific o0r application specific new authentication key
        // AFter a successsful format
        if(utils.changeKey(newAuthKey) == true)
            Log.d("New Authentication Key","changed ok");

        return true;
    }

    // Check that the card has been correctly formatted.
    protected boolean checkFormat() {
        // Read the card contents and check that all is ok.
        byte[] memory = utils.readMemory();
        if (memory == null)
            return false;

        // Check the application tag.
        for (int i = 1; i < 4; i++)
            if (memory[4 * 4 + i] != applicationTag[i])
                return false;

        // Check zeros. Ignore page 36 and up because of the safe mode.
        for (int i = 5 * 4; i < 36 * 4; i++)
            if (memory[i] != 0)
                return false;

        // Check that the memory pages 4..39 are not locked.
        // Lock 0: Check lock status for pages 4-7
        if (memory[2 * 4 + 2] != 0)
            return false;
        // Lock 1:
        if (memory[2 * 4 + 3] != 0)
            return false;
        // Lock 2:
        if (memory[40 * 4] != 0)
            return false;
        // Lock 1:
        if (memory[40 * 4 + 1] != 0)
            return false;

        return true;
    }



    public boolean issue( int expiryTime,int uses) throws GeneralSecurityException {
        utils.authenticate(newAuthKey);
        if (!checkFormat()) {
            System.err.print("Format error");
            return false;
        }
        // Dummy ticket with just an HMAC. You need to implement the rest.

        // Proper ticketing.

        // Write the expirity date to page 7
        //utils.writePages(ByteBuffer.allocate(4).putInt(expiryTime).array(), 0, 7, 1);

        // Write the remaining uses to page 8
        // Get the previous value if any in page 8, which means already the card has some rides left, and then add the
        // New issued rdies value to it, avoids over writing and addition of new rides without affecting the old issued rides
        byte[] remainingUsesByte = new byte[4];
        utils.readPages(8, 1, remainingUsesByte, 0);
        remainingUses = ByteBuffer.wrap(remainingUsesByte).getInt();
        remainingUses = uses + remainingUses;

        utils.writePages(ByteBuffer.allocate(4).putInt(remainingUses).array(), 0, 8, 1);

        //Page 9 - Hold the total number of issued rides.
        utils.writePages(ByteBuffer.allocate(4).putInt(remainingUses).array(), 0, 9, 1);

        // Page 10  specifies the page number where the next history goes, it helps in maintaing the circular feature of
        //History pages , that is the older history gets over written
        //Page to start the History
        if(remainingUses == 0)
            utils.writePages(ByteBuffer.allocate(4).putInt(11).array(), 0, 10, 1);


        // Currently it only reads first 5 pages.
        byte[] dataOnCard = new byte[15 * 4];
        utils.readPages(0, 15, dataOnCard, 0);

        // ignore locks and OTP bits
        for (int ig = 0; ig < 6; ig ++){
            dataOnCard[10+ig] = 0;
        }

        byte[] mac = macAlgorithm.generateMac(dataOnCard);
        // We only use 8 bytes (64 bits) of the MAC.
        utils.writePages(mac, 0, 5, usedMacLength);

        // Changes the authentication key
       // utils.changeKey(authenticationKey);

        // Sets Auth0 and Auth1 settings
        utils.setAuth0(3);//Authentic
        // ation is required from page 3
        //utils.setAuth1(true);// true: Authentication is required for read & write; false: Authentication is require for write only
        utils.setAuth1(false);// true: Authentication is required for read & write; false: Authentication is require for write only

        return true;
    }

    // Use the ticket once.
    public void use(int currentTime) throws GeneralSecurityException {
        isValid = true;

       // utils.authenticate(authenticationKey);
        if(!utils.authenticate(newAuthKey))
            isValid = false;
        //utils.authenticate(newAuthKey);




        byte[] dataOnCard = new byte[15 * 4];
        byte[] macOnCard = new byte[2 * 4];
        utils.readPages(0, 15, dataOnCard, 0);
        utils.readPages(5, usedMacLength, macOnCard, 0);

        // ignore locks and OTP bits
        for (int ig = 0; ig < 6; ig++) {
            dataOnCard[10 + ig] = 0;
        }
        byte[] mac = macAlgorithm.generateMac(dataOnCard);
        // We only use 8 bytes (64 bits) of the MAC.
        for (int i = 0; i < usedMacLength * 4; i++) {
            if (macOnCard[i] != mac[i]) {
                infoToShow = "Invalid Ticket";
                isValid = false;
            }
        }




        // Dummy ticket use that validates only the HMAC. You need to implement the rest.

        // TODO: Create methods to read from card and store to the card
        // need to update the new remaining uses of the card.

        //Check for quick usage - currently checks that within one minute we cannot resuse the card - i.e. cannot swipte the
        //Card again within one minute cna be extended

        //TODO: Implement proper ticketing.

        if(isValid()) {
            checkQuickUsage();

            if (quick == 0) {
                infoToShow = "Quick Usage: Wait for 1 Minute!";
                isValid = false;
            }

            // Retrieve the remaining uses from the card at page 8
            byte[] remainingUsesByte = new byte[4];
            utils.readPages(8, 1, remainingUsesByte, 0);
            remainingUses = ByteBuffer.wrap(remainingUsesByte).getInt();

            // Retrieve the remaining uses from the card at page 8
            int totalIssuedNum = 0;
            byte[] totalIssued = new byte[4];
            utils.readPages(9, 1, totalIssued, 0);
            totalIssuedNum = ByteBuffer.wrap(totalIssued).getInt();

            //Set the expiry time on the first use - check for the remaining uses and total rides allocated/issued.
            //When no rides are used we know its the first ride and we set the exprity time
            if (totalIssuedNum == remainingUses) {
                //Very first usage set the expiration time
                int days = 30;
                int expiryTime = currentTime + days * 24 * 60;
                utils.writePages(ByteBuffer.allocate(4).putInt(expiryTime).array(), 0, 7, 1);

            }

            // Retrieve the expiry time from card at page 7
            byte[] expiryTimeByte = new byte[4];
            utils.readPages(7, 1, expiryTimeByte, 0);
            expiryTime = ByteBuffer.wrap(expiryTimeByte).getInt();


            //TODO: Implement proper ticketing.

            if (isValid()) {

                if (expiryTime < currentTime) {
                    infoToShow = "Ticket Expired!";
                    isValid = false;
                } else if (remainingUses == 0) {
                    infoToShow = "No more rides available";
                    isValid = false;
                } else if (isValid()) {
                    // This string will be shown after ticket is used in test mode. Make
                    // your own info string.
                    infoToShow = "Ticket Valid";
                    isValid = true;
                    //expiryTime = 0;
                    remainingUses--;

                    // Write the remaining uses to page 8

                    utils.writePages(ByteBuffer.allocate(4).putInt(remainingUses).array(), 0, 8, 1);

                    //After a succcessful use write the details in History which will show the history in console
                    writeinHistory();

                    // Currently it only reads first 5 pages.
                    dataOnCard = new byte[15 * 4];
                    utils.readPages(0, 15, dataOnCard, 0);

                    // ignore locks and OTP bits
                    for (int ig = 0; ig < 6; ig ++){
                        dataOnCard[10+ig] = 0;
                    }

                    mac = macAlgorithm.generateMac(dataOnCard);
                    // We only use 8 bytes (64 bits) of the MAC.
                    utils.writePages(mac, 0, 5, usedMacLength);


                }
            }
        }

        if (!isValid)
            System.err.print(infoToShow);
    }

    // After validation, get ticket status: was it valid or not?
    public boolean isValid() {
        return isValid;
    }

    // After validation, get the number of remaining uses.
    public int getRemainingUses() {
        return remainingUses;
    }

    // After validation, get the expiry time.
    public int getExpiryTime() {
        return expiryTime;
    }

    /**
     * Function: writeinHistory
     * @Paramin - nothing
     * @ param out - none
     * Gets the current time and updates the history in a circular manner - overwrite the oldest history
     * end prints the hisotry in console
     */


        public void writeinHistory() {
            int currentTime = (int) ((new Date()).getTime() / 1000 / 60);
            int page= 0;
            byte[] pagetoWrite = new byte[4];
            utils.readPages(10, 1, pagetoWrite, 0);
            page = ByteBuffer.wrap(pagetoWrite).getInt();

            utils.writePages(ByteBuffer.allocate(4).putInt(currentTime).array(), 0, page, 1);

            page = page +1;

            if (page > 15)
                page=11; //Circle to over write the older ones

            utils.writePages(ByteBuffer.allocate(4).putInt(page).array(), 0, 10, 1);
            printHistory();



        }

    /**
     * Function printHistory
     * @Paramin- none
     * @paramout- none
     * Prints history of the last five usages
     */



    public void printHistory() {
        int resp = 0;
        Log.d("History:", "Recent Five Usages:");


        Format formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");


        for (int page = 11; page < 16; page++) {
            resp = 0;
            byte[] pagetoWrite = new byte[4];
            utils.readPages(page, 1, pagetoWrite, 0);
            resp = ByteBuffer.wrap(pagetoWrite).getInt();
            if (resp != 0) {
                Date date = new Date((long) resp * 60 * 1000);
                String s = formatter.format(date);
                Log.d("Usage: Date/Time", s);

            }

        }
    }

    /**
     * Function: checkQuickUSage()
     * @paramin: none
     * @paramout: none
     * @Returns: none
     * Function to check quick usage, get the last usage data from history page and compare it
     * with the current time and if the difference is less than a minute donot allow the use.
     * USer needs to wait for a minute touse the card again (One minut ecna be chagned and made configurable)
     */


    public void checkQuickUsage() {
        int page, last;
        byte[] pagetoWrite = new byte[4];
        utils.readPages(10, 1, pagetoWrite, 0);
        page = ByteBuffer.wrap(pagetoWrite).getInt();

        if (page == 11)
            page = 15;
        else
            page = page - 1;


        byte[] lasttime = new byte[4];
        utils.readPages(page, 1, lasttime, 0);
        last = ByteBuffer.wrap(lasttime).getInt();
        int currentTime = (int) ((new Date()).getTime() / 1000 / 60);
        int delata = currentTime - last;
        quick = 1;
        if (delata < 1) {
            quick = 0;

        }

    }



}
