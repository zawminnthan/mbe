package com.ithub.mbe.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ithub.mbe.security.component.Crypto;
import com.ithub.mbe.security.component.DigitalSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;

import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.*;

public class QRService {

    /**
     * logger
     */
    Logger logger = LoggerFactory.getLogger(QRService.class);

    /**
     * DATE_FORMAT
     */
    public final static String DATE_FORMAT = "dd/MM/yyyy@HH-mm-ss";

    /**
     * crypto
     */
    @Autowired
    private Crypto crypto;

    /**
     * digitalSignature
     */
    @Autowired
    private DigitalSignature digitalSignature;


    /**
     * wc
     */
    @Autowired
    private WebClient wc;

    /**
     *
     * @return
     */
    private Flux<String> purchaseQR(){

        /*return wc.get()
                .uri ("/get/all")
                .retrieve ()
                .bodyToFlux (String.class)
                .timeout (Duration.ofMillis (1000));*/

        return wc.post()
                .uri("")
                .retrieve()
                .bodyToFlux(String.class)
                .timeout(Duration.ofMillis(1000))
                .retry(3);
    }

    /**
     * @return
     * @throws JsonProcessingException
     */
    private String generatePurchaseRequestData(int isMobile) throws Exception {


        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> reqBody = new HashMap<>();
        Map<String, Object> App_Ticket_Request = new HashMap<>();

        Map<String, Object> Ticket_Signature = new HashMap<>();
        Map<String, Object> QR_Ticket_Request = new HashMap<>();
        QR_Ticket_Request.put("Requester_ID", isMobile > 1 ? "50" : "60"); //if isMobile>1 - > Mobile, else TOM
        QR_Ticket_Request.put("Language", "0");
        QR_Ticket_Request.put("TXN_Ref_No", generateRandomBase64Token(21));
        QR_Ticket_Request.put("TXN_Date", getDatTimeString(new Date(), DATE_FORMAT));
        QR_Ticket_Request.put("PSP_Specific_Data", "78;Merchant15;MO-1;300;IMPS;5467908;Merchant15_20200612_00312");
        QR_Ticket_Request.put("Booking_Lat", "0");
        QR_Ticket_Request.put("Booking_Lon", "0");
        QR_Ticket_Request.put("Mobile", "9538515161");

        Map<String, Object> TicketBlock = new HashMap<>();
        Map<String, Object> DynamicBlock = new HashMap<>();
        Map<String, Object> OperatorID1 = new HashMap<>();

        OperatorID1.put("OpID", "3");
        OperatorID1.put("NoOfTickets", "1");

        Map<String, Object> TicketInfo = new HashMap<>();
        Map<String, Object> TicketInfo1 = new HashMap<>();
        TicketInfo1.put("Grp_Size", "1");
        TicketInfo1.put("Src_Stn", "11");
        TicketInfo1.put("Dest_Stn", "10");
        TicketInfo1.put("Activation_Date", getDatTimeString(new Date(), DATE_FORMAT));
        TicketInfo1.put("Validity", "480");
        TicketInfo1.put("Ticket_Fare", "9.50");
        TicketInfo1.put("Product_Id", "01");
        TicketInfo1.put("Service_Id", "01");
        TicketInfo1.put("Duration", "180");
        TicketInfo.put("TicketInfo1", TicketInfo1);

        OperatorID1.put("TicketInfo", TicketInfo);
        DynamicBlock.put("OperatorID1", OperatorID1);
        TicketBlock.put("DynamicBlock", DynamicBlock);

        QR_Ticket_Request.put("TicketBlock", TicketBlock);

        App_Ticket_Request.put("QR_Ticket_Request", QR_Ticket_Request);

        String qrTicketReq = prepareJsonStringByRootName("QR_Ticket_Request", QR_Ticket_Request);
        //String qrTestData = "\"QR_Ticket_Request\":{\"Requester_ID\":\"50\",\"Language\":\"0\",\"TXN_Ref_No\":\"1670554731\",\"TXN_Date\":\"09/12/2022@10-58-51\",\"PSP_Specific_Data\":\"78;Mechant;MD-1;300;456456;Merchant1S_2020612_00312\",\"Booking_Lat\":\"28605\",\"Booking_Lon\":\"77299\",\"Mobile\":\"9201345678\",\"TicketBlock\":{\"DynamicBlock\":{\"OperatorID1\":{\"OpID\":\"10\",\"NoOfTickets\":\"1\",\"TicketInfo\":{\"TicketInfo1\":{\"Grp_Size\":\"1\",\"Src_Stn\":\"14\",\"Dest_Stn\":\"14\",\"Activation_Date\":\"09/12/2022@10-58-51\",\"Product_Id\":\"0\",\"Service_Id\":\"1\",\"Ticket_Fare\":\"10\",\"Validity\":\"480\",\"Duration\":\"180\"}}}}}}";
        //String sign = "kKJvr00QL4kzjjhJxYoqCvWoDlF+Z3P2Gj+fdmiLLLM+K2fk6Wt0ZVmEdaxUIbMmazBVg8cAQ8868m04RlMh3zRS92D07CPeJKFe73WOluWCNk6gqv9RMlcBswxk4TMMBIb7LkWJxrA/imyu849gyWa5lo+s0nfJr2xCAgcnT/K2VxkoaZvY4eBM3x+qBLmRJRFaDDq/HvKLxG1ztdX22tT6CVKVvsvlo3BoTmYsuAqyc27CtSNac2BrPW0r1/qGyTVA6g0viAo9sl4aUN3IXsyIghL33E0uVZGSjkHi5A49aVBpK7TdHyQD+x/BCAh9fUw5ppNzVKvs2hAzE6D10A==";
        //byte[] signatureBytes = Base64.getDecoder().decode(sign);
        //byte[] signData= digitalSignature.signingL2(qrTicketReq, crypto.getPrivateKey("rsa/00050/rsa_private_pkcs1"));
        //boolean isVerify= digitalSignature.isVerifyL2(signatureBytes, qrTestData, crypto.getPublicKey("rsa/00050/rsa_public_pkcs8"));

        byte[] signData= digitalSignature.signingL2(qrTicketReq, crypto.getPrivateKey("rsa/00050/rsa_private_pkcs1"));
        //boolean isVerify= digitalSignature.isVerifyL2(signData, qrTestData, crypto.getPublicKey("rsa/00050/rsa_public_pkcs8"));


        //digital signature test
        /*String aa = Base64.getEncoder().encodeToString(signMsgs);
        byte[] bb = Base64.getDecoder().decode(aa);
        try{
            boolean f = digitalSignatureSigning.isVerifyL2(bb, signatureString, crypto.getPublicKey("keys/rsa_public_pkcs8"));
        }catch (Exception ex){
            ex.printStackTrace();
        }*/

        //return Base64.getEncoder().encodeToString(signMsgs);
        String Signature = Base64.getEncoder().encodeToString(signData);
        Ticket_Signature.put("Signature", Signature);
        App_Ticket_Request.put("Ticket_Signature", Ticket_Signature);

        reqBody.put("App_Ticket_Request", App_Ticket_Request);

        return objectMapper.writeValueAsString(reqBody);

    }

    public String getDatTimeString(Date date, String format) {
        SimpleDateFormat formatter = new SimpleDateFormat(format);
        return formatter.format(date);
    }

    public String generateRandomBase64Token(int byteLength) {
        UUID uniqueKey = UUID.randomUUID();
        return uniqueKey.toString().replace("-", "").substring(0,20);
    }

    /**
     *
     * @param rootName
     * @param requestObject
     * @return
     * @throws JsonProcessingException
     */
    public String prepareJsonStringByRootName(String rootName, Map<String, Object> requestObject) throws JsonProcessingException {

        //This may be need in future
        ObjectMapper mapper = new ObjectMapper();

        String jsonString = mapper.writeValueAsString(requestObject);
        jsonString = "\"".concat(rootName).concat("\"").concat(":").concat(jsonString);
        return jsonString;
    }
}
