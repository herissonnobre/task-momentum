"use client";
import React, { useState } from "react";
import api from "@/api";
import Link from "next/link";

export default function LoginPage() {
    const [formData, setFormData] = useState({
        email: "",
        password: "",
    });

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        try {
            const response = await api.post("/auth/login", formData);
            console.log("User authenticated successfully: ", response.data);

            if (response.data.token) {
                localStorage.setItem("token", response.data.token);
            }
        } catch (error) {
            console.error("Error on login request:", error);
        }
    };

    return (
        <div className="w-full h-full flex flex-col items-center justify-center">
            <div className="flex flex-col items-center justify-center">
                <h1 className="text-[57px] leading-[64px]">Task Momentum</h1>
                <form
                    className="flex flex-col items-center justify-center w-[380px]"
                    onSubmit={handleSubmit}
                >
                    <div className="flex flex-col w-full">
                        <div className="flex flex-col">
                            <div className="flex flex-col">
                                <label className="text-xs" htmlFor="email">
                                    E-mail
                                </label>
                                <input
                                    type="email"
                                    id="email"
                                    name="email"
                                    required
                                    onChange={handleChange}
                                />
                            </div>
                            <div className="flex flex-col">
                                <label className="text-xs" htmlFor="password">
                                    Senha
                                </label>
                                <input
                                    type="password"
                                    id="password"
                                    name="password"
                                    required
                                    onChange={handleChange}
                                />
                            </div>
                        </div>
                        <p className="text-xs self-end flex">
                            Esqueceu a senha. <Link href="/recuperar-senha">Clique aqui.</Link>
                        </p>
                    </div>
                    <button className="text-[14px] leading-5" type="submit">
                        Entrar
                    </button>
                </form>
                <p className="text-sm flex">
                    Não tem cadastro? <Link href="/cadastro">Clique aqui.</Link>
                </p>
            </div>
        </div>
    );
}
