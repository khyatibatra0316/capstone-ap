import express from "express";
import Book from "../models/Book.js";

const router = express.Router();

// GET ALL BOOKS
router.get("/", async (req, res) => {
  try {
    const books = await Book.find();
    res.json({ success: true, books });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET SINGLE BOOK BY ID
router.get("/:id", async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);
    if (!book)
      return res.status(404).json({ success: false, message: "Book not found" });

    res.json({ success: true, book });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ADD A NEW BOOK
router.post("/", async (req, res) => {
  try {
    const newBook = new Book(req.body);
    await newBook.save();
    res.json({ success: true, book: newBook });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

export default router;
