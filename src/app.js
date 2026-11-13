import express from "express";
import { router } from "./routes/domain.routes.js";

export const app = express();

app.use(express.json());

app.use("/api", router);
app.get("/", (req, res) => {
  res.send("Hello World!");
});
