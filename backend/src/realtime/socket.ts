import { Server as HttpServer } from "http";
import { Server } from "socket.io";

export let io: Server;

export function initSocket(httpServer: HttpServer) {
  io = new Server(httpServer, {
    cors: {
      origin: "*", // for dev. later put your frontend url
      methods: ["GET", "POST"],
    },
  });

  io.on("connection", (socket) => {
    console.log("🟢 WS connected:", socket.id);

    socket.on("disconnect", () => {
      console.log("🔴 WS disconnected:", socket.id);
    });
  });

  return io;
}
