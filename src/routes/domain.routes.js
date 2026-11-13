import express from "express";
import { domainCheck } from "../controller/domain.controller.js";

export const router = express.Router();

router.post("/domains/check", domainCheck);
