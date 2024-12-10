const Booking = require("../models/booking");
const { CreatePaymentRequest } = require("../utils/payment");
const sequelize = require('../config/database.js');
const Vehicle = require("../models/vehicle");
const Billing = require("../models/biling.js");
const generateBookingId = require("../utils/generatorID.js");

const CreateBooking = async(req, res, next) => {
    const {vehicleID, address, username, email, phone_number, total_days, driver, rental_date, payment_method} = req.body;
    console.log(req.body);
    const t = await sequelize.transaction();

    try {

        const vehicle = await Vehicle.findByPk(vehicleID);

        if (!vehicle) {
            return res.status(404).json({
                message: "Vehicle not found",
            })
        }

        if (vehicle.status === "booking") {
            return res.status(400).json({
                message: "Vehicle is already booking",
            })
        }


        total_amount = vehicle.price * total_days
        const billing_date = new Date();
        const formattedDate = billing_date.toLocaleDateString('en-CA')

        if (driver === "tanpa driver") {
            total_amount = total_amount + 200000
        } else  {
            total_amount = total_amount + 200000
        }

        const booking = await Booking.create({
            id: generateBookingId(),
            user_id: req.user.id,
            vehicle_id: vehicleID,  
            address,
            username,
            email,
            phone_number,
            total_days,
            driver,
            rental_date,
            total_amount
        })

         await Billing.create({
            booking_id: booking.id,
            total_amount,
            payment_method,
            billing_date: formattedDate,
        })

        const chargeResponse = await CreatePaymentRequest(booking.id, total_amount, email, username, phone_number, payment_method);

        await t.commit();

        res.status(201).json({
            message: 'Booking created successfully',
            data: {
                booking,
                chargeResponse
            }
        })
        
    } catch (error) {
        await t.rollback();
        res.status(500).json({ message: 'Server error', error: error.message })
    }
}

const GetBooking = async(req, res, next) => {

    try {
        const bookings = await Booking.findAll({  
            attributes: ['id', 'rental_date', "total_days","total_amount", "username","status"],
            include: [ {
                model: Vehicle,
                as: 'vehicle', // Alias defined in the association
                attributes: ['name'], // Specify only the fields you need from the Vehicle model
              },
            ],
        })

        res.status(200).json({
            message: "Get all booking successful",
            data: {
                bookings
            }
        })
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message })
    }
}


const GetBookingByID = async(req, res, next) => {  
    const {bookingID} = req.params;

    try {
        const booking = await Booking.findOne({ where: {id: bookingID}})

        if (!booking) { 
            return res.status(404).json({
                message: "Booking not found",
            })
        }

        res.status(200).json({
            message: "Get booking by ID successful",
            data: {
                booking 
            }
        })

    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message })
    }
} 

const GetBookingByUserID = async(req, res, next) => {  
    const {id} = req.user;

    try {
        const bookings = await Booking.findAll({ where: {user_id: id},  
            attributes: ['id', 'rental_date', "total_days","total_amount","status"],
            include: [ {
                model: Vehicle,
                as: 'vehicle', // Alias defined in the association
                attributes: ['name'], // Specify only the fields you need from the Vehicle model
              },
            ],
        })

        res.status(200).json({
            message: "Get booking by user ID successful",
            data: {
                bookings
            }
        })

    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message })
    }
}


const ConfirmBookingPayment = async(req, res, next) => {
    const {order_id, transaction_status, fraud_status} = req.body;
  
    let bookingID = order_id;
    let transactionStatus = transaction_status;
    let fraudStatus = fraud_status;

    console.log(bookingID, transactionStatus, fraudStatus)
    try {
        if (transactionStatus == 'capture') {

            if (fraudStatus == 'challenge') {
                await sequelize.transaction(async (t) => {
                    await Booking.update({status: "canceled"}, {where: {id: bookingID}, transaction: t})
                    await Billing.update({status: "deny"}, {where: {booking_id: bookingID}, transaction: t})

                    res.status(200).json({
                        "fraud_status": "challenge",
                        "order_id": bookingID
                    })
                })
            

            } else if (fraudStatus == 'accept') { 

                await sequelize.transaction(async (t) => {
                    await Booking.update({status: "completed"}, {where: {id: bookingID}, transaction: t})
                    await Billing.update({status: "accepted"}, {where: {booking_id: bookingID}, transaction: t})
                     // Retrieve the updated booking
                    const booking = await Booking.findOne({ where: { id: bookingID }, transaction: t });
                    await Vehicle.update({status: "booking"}, {where: {id: booking.vehicle_id}, transaction: t})
                    res.status(200).json({
                        "fraud_status": "accept",
                        "order_id": bookingID
                    })
                }) 
            }
        } else if (transactionStatus == 'settlement') {
            await sequelize.transaction(async (t) => {
                console.log(bookingID)
                 await Booking.update({status: "completed"}, {where: {id: bookingID}, transaction: t})
             
                 // Retrieve the updated booking
                const booking = await Booking.findOne({ where: { id: bookingID }, transaction: t });
                await Billing.update({status: "accepted"}, {where: {booking_id: bookingID}, transaction: t})
                await Vehicle.update({status: "booking"}, {where: {id: booking.vehicle_id}, transaction: t})
                res.status(200).json({
                    "fraud_status": "accept",
                    "order_id": bookingID
                })
            }) 
        } else if (transactionStatus == 'deny') {
            await sequelize.transaction(async (t) => {
                await Booking.update({status: "canceled"}, {where: {id: bookingID}, transaction: t})
                await Billing.update({status: "deny"}, {where: {booking_id: bookingID}, transaction: t})

                res.status(200).json({
                    "fraud_status": "challenge",
                    "order_id": bookingID
                })
            })
        } else if (transactionStatus == 'cancel' || transactionStatus == 'expire') {
            await sequelize.transaction(async (t) => {
                await Booking.update({status: "canceled"}, {where: {id: bookingID}, transaction: t})
                await Billing.update({status: "expired"}, {where: {booking_id: bookingID}, transaction: t})

                res.status(200).json({
                    "fraud_status": "challenge",
                    "order_id": bookingID
                })
            }) 
        } 
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Server error', error: error.message })
    }
  

}






module.exports = {CreateBooking, GetBooking, GetBookingByID, GetBookingByUserID, ConfirmBookingPayment};