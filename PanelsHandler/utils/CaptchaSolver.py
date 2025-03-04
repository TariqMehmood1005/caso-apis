import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import tensorflow as tf
import logging
import numpy as np

tf.get_logger().setLevel(logging.ERROR)
from PanelsHandler.utils.CaptchSolverLayers import *


class CaptchaSolver(object):
    def __init__(
            self,
            image_shape: tuple = (40, 120),
            max_length: int = 5,
            captcha_model_path: str = "PanelsHandler/TrainedModels/captcha_solver_v1.keras",
            vocab: list = None
    ) -> None:
        if vocab is None:
            vocab = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        self.__image_shape: tuple = image_shape
        self.__max_length: int = max_length
        self.__char_to_num = tf.keras.layers.StringLookup(
            vocabulary=vocab,
            mask_token=None
        )
        self.__num_to_char = tf.keras.layers.StringLookup(
            vocabulary=self.__char_to_num.get_vocabulary(), mask_token=None, invert=True
        )
        self.__trained_captcha_solver_model_path: str = os.path.abspath(
            path=captcha_model_path
        ).__str__()

    async def __load_model(self):
        return tf.keras.models.load_model(self.__trained_captcha_solver_model_path)

    @staticmethod
    async def __ctc_decode(
            y_predictions: any,
            input_length: any,
            greedy: bool = True,
            beam_width: int = 100,
            top_paths: int = 1
    ) -> tuple:
        input_shape = tf.keras.ops.shape(y_predictions)
        num_samples, num_steps = input_shape[0], input_shape[1]
        y_predictions = tf.keras.ops.log(
            tf.keras.ops.transpose(y_predictions, axes=[1, 0, 2]) + tf.keras.backend.epsilon()
        )
        input_length = tf.keras.ops.cast(input_length, dtype="int32")

        if greedy:
            (decoded, log_prob) = tf.nn.ctc_greedy_decoder(
                inputs=y_predictions, sequence_length=input_length
            )
        else:
            (decoded, log_prob) = tf.compat.v1.nn.ctc_beam_search_decoder(
                inputs=y_predictions,
                sequence_length=input_length,
                beam_width=beam_width,
                top_paths=top_paths,
            )
        decoded_dense = []
        for st in decoded:
            st = tf.SparseTensor(st.indices, st.values, (num_samples, num_steps))
            decoded_dense.append(tf.sparse.to_dense(sp_input=st, default_value=-1))
        return decoded_dense, log_prob

    async def __decode_batch_predictions(self, predictions: any) -> list[str]:
        input_len = np.ones(predictions.shape[0]) * predictions.shape[1]
        results = await self.__ctc_decode(predictions, input_length=input_len, greedy=True)
        results = results[0][0][:, :self.__max_length]
        output_text = []
        for res in results:
            res = tf.strings.reduce_join(self.__num_to_char(res)).numpy().decode("utf-8")
            output_text.append(res)
        return output_text

    async def predict_from_image_path(self, image_path: str) -> str:
        model = await self.__load_model()
        img = tf.io.read_file(filename=image_path)
        img = tf.io.decode_png(contents=img, channels=1)
        img = tf.image.convert_image_dtype(image=img, dtype=tf.float32)
        final_image = tf.image.resize(images=img, size=self.__image_shape)
        img = tf.keras.ops.transpose(final_image, axes=[1, 0, 2])
        img = tf.expand_dims(input=img, axis=0)
        prediction_model = tf.keras.models.Model(
            model.input[0], model.get_layer(name="dense2").output
        )
        predictions = prediction_model.predict(img, verbose=0)
        predicted_texts = await self.__decode_batch_predictions(predictions)
        return predicted_texts[0]


