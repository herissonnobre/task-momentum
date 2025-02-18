export default function LoginPage() {
    return (
        <div className="w-full h-full flex flex-col items-center justify-center">
            <div className="flex flex-col items-center justify-center">
                <h1 className="text-[57px] leading-[64px]">Task Momentum</h1>
                <form className="flex flex-col items-center justify-center w-[380px]">
                    <div className="flex flex-col w-full">
                        <div className="flex flex-col">
                            <div className="flex flex-col">
                                <label className="text-xs" htmlFor="email">
                                    E-mail
                                </label>
                                <input type="email" id="email" name="email" required />
                            </div>
                            <div className="flex flex-col">
                                <label className="text-xs" htmlFor="password">
                                    Senha
                                </label>
                                <input type="password" id="password" name="password" required />
                            </div>
                        </div>
                        <p className="text-xs self-end flex">
                            Esqueceu a senha. <p>Clique aqui.</p>
                        </p>
                    </div>
                    <button className="text-[14px] leading-5" type="submit">
                        Entrar
                    </button>
                </form>
                <p className="text-sm flex">
                    Não tem cadastro? <p>Clique aqui.</p>
                </p>
            </div>
        </div>
    );
}
