const Vehicle = require("../models/vehicle.js")
const GetVehicles = async(req, res, next) => {
    try {
        const vehicles = await Vehicle.findAll()
        res.status(200).json({
            message: "Get all vehicles successful",
            data: {
                vehicles
            }
        })
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message })
    }
}

const GetVehicleByID = async (req, res, next) => {
    const {vehicleID} = req.params

    try {
        const vehicle = await Vehicle.findOne({where: {id: vehicleID}})

        if (!vehicle) {
            return res.status(404).json({
                message: "Vehicle not found",
            })
        }
        res.status(200).json({
            message: `Get vehicles by id ${vehicleID} successful`, 
            data: {
                vehicle
            }
        });

    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message })
    }
}


const CreateVehicle = async (req, res, next) => {
    const {name, type, category, transmission_type, passenger_capacity, price,  air_conditioner, doors} = req.body    
    const {file} = req

    try {
        if (!file) {
            return res.status(400).json({
                message: "Image is required",
                error: 'Please upload an image file'
            })
        }
        const vehicle = await Vehicle.create({
            name,
            type,
            category,
            transmission_type,
            passenger_capacity,
            price,
            air_conditioner: air_conditioner === 'True' ? true : false,
            doors,
            image: `uploads/${file.filename}`
        })

        res.status(200).json({
            message: "Create vehicle successful",
            data: {
                vehicle
            }
        })
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message })
    }
}


const DeleteVehicle = async (req, res, next) => {
    const {vehicleID} = req.params

    try {
        const vehicle = await Vehicle.findOne({where: {id: vehicleID}})

        if (!vehicle) {
            return res.status(404).json({
                message: "Vehicle not found",
            })
        }

        await vehicle.destroy()
        res.status(200).json({
            message: `Delete vehicle successful`, 
            data: {
                vehicle
            }
        });

    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message })
    }
}


const UpdateVehicle = async (req, res, next) => {
    const {vehicleID} = req.params
    const {name, type, category, transmission_type, passenger_capacity, price,  air_conditioner, doors} = req.body    
    const {file} = req

    try {
        if (!file) {
           const vehicle = await Vehicle.update({
            name,
            type,
            category,
            transmission_type,
            passenger_capacity,
            price,
            air_conditioner: air_conditioner === 'True' ? true : false,
            doors,
           }, {where: {id: vehicleID}})
           console.log(vehicle)
            return res.status(200).json({
                message: `Update vehicle successful`, 
                data: {
                    vehicle
                }
            });
            
        } else {
            const vehicle = await Vehicle.update({
                name,
                type,
                category,
                transmission_type,
                passenger_capacity,
                price,
                air_conditioner: air_conditioner === 'True' ? true : false,
                doors,
                image: `uploads/${file.filename}`
            }, {where: {id: vehicleID}})

            return res.status(200).json({
                message: `Update vehicle successful`, 
                data: {
                        vehicle
                }
            });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message })
    }

}

module.exports = {GetVehicles,GetVehicleByID, DeleteVehicle, CreateVehicle, UpdateVehicle};