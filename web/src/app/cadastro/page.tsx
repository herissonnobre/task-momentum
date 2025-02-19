"use client";
import React, { useState } from "react";
import api from "@/api";
import Link from "next/link";

export default function LoginPage() {
    const [formData, setFormData] = useState({
        full_name: "",
        email: "",
        password: "",
    });

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        try {
            const response = await api.post("/auth/register", formData);
            console.log("User registered successfully: ", response.data);

            if (response.data.token) {
                localStorage.setItem("token", response.data.token);
            }
        } catch (error) {
            console.error("Error on register request:", error);
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
                            <label htmlFor="full_name" className="text-xs">
                                Nome completo
                            </label>
                            <input
                                type="text"
                                id="full_name"
                                name="full_name"
                                required
                                onChange={handleChange}
                            />
                        </div>

                        <div className="flex flex-col">
                            <label htmlFor="email" className="text-xs">
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
                            <label htmlFor="password" className="text-xs">
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

                    <button type="submit" className="text-[14px] leading-5">
                        Cadastrar
                    </button>
                </form>

                <p className="text-sm flex">
                    Já tem cadastro? <Link href="/entrar">Clique aqui.</Link>
                </p>
            </div>
        </div>
    );
}
