const SnapApi = require("../config/midtans.js");

const CreatePaymentRequest = async (bookId, grossAmount, email, username, phone_number, paymentMethod) => {
    let parameter = {
        payment_type: paymentMethod,
        transaction_details: {
          order_id: bookId,
          gross_amount: grossAmount,
      },
        credit_card:{
            secure: true
        },
        customer_details: {
            first_name: username,
            last_name: "",
            email: email,
            phone: phone_number
        },
        enabled_payments: [
            paymentMethod
        ],    
        callbacks: {
          finish: `${process.env.MIDTRANS_CALLBACK_URL}/`
        },
      };
      
    const chargeResponse = await SnapApi.createTransaction(parameter);

    return chargeResponse
}

module.exports = {CreatePaymentRequest}



