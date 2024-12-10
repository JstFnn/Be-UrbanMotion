const Booking = require("../models/booking");
const {QueryTypes} = require('sequelize');
const User = require("../models/user");


const DashboardData = async(req, res, next) => {
  const currentYear = new Date().getFullYear(); // Tahun saat ini
  const currentMonth = new Date().getMonth() + 1;
  const monthNames = [
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
  ];

  try {
    const userCount = await User.count();
    const bookingCount = await Booking.count({
      where: {
        status: 'completed', // Filter for 'completed' status
      },
    });

    const totalRevenue = await Booking.sequelize.query(
      `
      SELECT 
        SUM(total_amount) AS total_revenue 
      FROM bookings
      WHERE YEAR(createdAt) = :year
        AND MONTH(createdAt) = :month
        AND status = 'completed'
      `,
      {
        replacements: { year: currentYear, month: currentMonth },
        type: QueryTypes.SELECT,
      }
    );

    const results = await Booking.sequelize.query(
      `
      SELECT 
        MONTH(createdAt) AS month, 
        SUM(total_amount) AS sales
      FROM bookings
      WHERE YEAR(createdAt) = :year AND status = 'completed'
      GROUP BY MONTH(createdAt)
      ORDER BY MONTH(createdAt)
      `,
      {
        replacements: { year: currentYear },
        type: QueryTypes.SELECT,
      }
    );

    // Buat array dengan semua bulan, default total_amount = 0
    const completeResults = Array.from({ length: 12 }, (_, index) => ({
      name: monthNames[index],
      sales: 0,
    }));

    // Isi data bulan yang ada dari hasil query
    results.forEach(result => {
      const monthIndex = result.month - 1; // Sesuaikan index bulan (1-based ke 0-based)
      completeResults[monthIndex].sales = result.sales || 0;
    });

    res.status(200).json({
      message: "Get dashboard data successful",
      data: {
        totalUsers: userCount,
        totalRentals: bookingCount,
        totalRevenue: totalRevenue[0].total_revenue || 0,
        grafik_data: completeResults,
      }
    });
        
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message })
    }
}


module.exports = {DashboardData}