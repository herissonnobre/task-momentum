export default function LoginPage() {

    return (
        <div>
            <div>
                <h1>Task Momentum</h1>

                <form>
                    <div>
                        <label htmlFor="email">E-mail</label>
                        <input type="email" id="email" name="email" required />
                    </div>

                    <button type="submit">Enviar</button>
                </form>

            </div>
        </div>
    );
}
